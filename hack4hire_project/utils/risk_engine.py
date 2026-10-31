import copy
import json
import os

from utils.detection_engine import SEVERITIES

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config', 'risk_scoring.json')
WEIGHT_NAMES = ('severity', 'evidence_confidence', 'ioc_ioa_signals', 'behavioral_anomalies', 'attack_progression')
LEVEL_ORDER = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')


def load_scoring_config(path=CONFIG_PATH):
    with open(path, encoding='utf-8') as handle:
        return json.load(handle)


def validate_settings(data):
    """Check analyst-supplied weights and thresholds. Returns them cleaned, or raises ValueError."""
    if not isinstance(data, dict) or not isinstance(data.get('weights'), dict) or not isinstance(data.get('levels'), dict):
        raise ValueError('Expected weights and levels')
    try:
        weights = {name: float(data['weights'][name]) for name in WEIGHT_NAMES}
        levels = {name: int(data['levels'][name]) for name in LEVEL_ORDER}
    except (KeyError, TypeError, ValueError):
        raise ValueError(f"weights need {', '.join(WEIGHT_NAMES)} and levels need {', '.join(LEVEL_ORDER)}, all numeric")
    if any(value < 0 for value in weights.values()) or round(sum(weights.values()), 6) != 100:
        raise ValueError('Weights cannot be negative and must add up to 100')
    if levels['LOW'] != 0 or not 0 < levels['MEDIUM'] < levels['HIGH'] < levels['CRITICAL'] <= 100:
        raise ValueError('Thresholds must rise from LOW = 0 through MEDIUM and HIGH to CRITICAL, at most 100')
    return {'weights': weights, 'levels': levels}


def apply_overrides(config, overrides):
    """The scoring config with an analyst's saved weights and thresholds on top"""
    merged = copy.deepcopy(config)
    merged['risk'].update(overrides or {})
    return merged


def _severity_rank(severity):
    return SEVERITIES.index(severity) if severity in SEVERITIES else 0


def risk_level_for(score, levels):
    return next(level for level, minimum in sorted(levels.items(), key=lambda item: -item[1]) if score >= minimum)


def score_incident(alerts, config=None, anomalies=()):
    """Compute severity, confidence and risk for a set of alerts, each with its reasons.

    Severity is potential impact: the highest severity among the alerts.
    Confidence is strength of evidence: independent rules reinforce each other, and an
    alert counts less when its link to the incident is weaker.
    Risk is investigation priority, not the probability that an attack is real: a weighted
    sum of the factors below. A repeat of one rule adds nothing to any factor. Behavioral
    baselines, model predictions and anomaly findings are alternatives within one factor, so
    the same unusual activity is not counted three times, and none of them can reach CRITICAL alone.
    """
    config = config or load_scoring_config()
    settings = config['risk']
    weights = settings['weights']

    # Severity
    top = max(alerts, key=lambda a: _severity_rank(a['severity']))
    severity = top['severity']
    severity_reason = f"Highest severity among {len(alerts)} alert(s): {top['rule_id']} {top['rule_name']} is {severity}."

    # Confidence: best alert per rule, so repeats of one rule do not count as new evidence
    best_per_rule = {}
    for alert in alerts:
        link = alert.get('correlation_score')
        link = 1.0 if link is None else link
        weighted = alert['confidence'] * link
        if weighted > best_per_rule.get(alert['rule_id'], (0, ''))[0]:
            best_per_rule[alert['rule_id']] = (weighted, f"{alert['rule_id']}: {alert['confidence']}% x link {link:.2f}")
    doubt = 1.0
    for weighted, _ in best_per_rule.values():
        doubt *= 1 - weighted / 100
    confidence = min(99, round((1 - doubt) * 100))
    confidence_reasons = [reason for _, reason in best_per_rule.values()]

    # Risk
    components = []

    def add(factor, share, reason):
        weight = weights[factor] if factor in weights else 0
        components.append({'factor': factor, 'weight': weight, 'share': round(share, 3),
                           'points': round(weight * share, 1), 'reason': reason})

    add('severity', settings['severity_factor'][severity], f'Incident severity is {severity}.')
    add('evidence_confidence', confidence / 100, f'Combined evidence confidence is {confidence}%.')

    ioa_rules = {a['rule_id'] for a in alerts if a.get('detection_type', 'IOA') == 'IOA'}
    ioc_alerts = [a for a in alerts if a.get('detection_type') == 'IOC']
    best_ioc = max((a['confidence'] for a in ioc_alerts), default=0)
    signals = settings['signals']
    ioa_share = min(1, (len(ioa_rules) + 1) / (signals['rules_for_full_share'] + 1)) if ioa_rules else 0
    add('ioc_ioa_signals', signals['ioa_share'] * ioa_share + signals['ioc_share'] * best_ioc / 100,
        f"{len(ioa_rules)} distinct behavior rule(s), {len(ioc_alerts)} threat intelligence match(es)"
        + (f', best confidence {best_ioc}%.' if ioc_alerts else '.'))

    ueba_alerts = [a for a in alerts if a.get('detection_type') == 'UEBA']
    ml_alerts = [a for a in alerts if a.get('detection_type') == 'ML']
    best_ueba = max((a['confidence'] for a in ueba_alerts), default=0)
    best_ml = max((a['confidence'] for a in ml_alerts), default=0)
    best_anomaly = max((a['strength'] for a in anomalies), default=0)
    behavior_reasons = []
    if ueba_alerts:
        behavior_reasons.append(f"{len(ueba_alerts)} behavioral anomaly(ies) against the entity's own baseline, best confidence {best_ueba}%")
    if ml_alerts:
        behavior_reasons.append(f'{len(ml_alerts)} network model prediction(s), weight {best_ml}%, uncalibrated')
    if anomalies:
        behavior_reasons.append(f'{len(anomalies)} statistically unusual activity window(s), strength {best_anomaly} of 100')
    add('behavioral_anomalies', max(best_ueba, best_ml, best_anomaly) / 100,
        ('; '.join(behavior_reasons) + '. The strongest one counts.') if behavior_reasons
        else 'No behavioral anomaly was found, or the entity has too little history to judge.')

    tactics = tactics_in_order(alerts)
    progression = settings['progression']
    tactic_share = min(1, max(0, len(tactics) - 1) / progression['tactics_for_full_share'])
    alert_share = min(1, (len(best_per_rule) - 1) / progression['detections_for_full_share'])
    add('attack_progression', progression['tactic_share'] * tactic_share + (1 - progression['tactic_share']) * alert_share,
        f"{len(tactics)} MITRE tactic(s) across {len(best_per_rule)} distinct detection(s): {', '.join(tactics) or 'none mapped'}.")

    # Asset importance sits on top of the weights, and on its own cannot reach another level
    assets = config.get('asset_criticality', {})
    touched = {}
    for alert in alerts:
        for field in ('hostname', 'src_ip', 'dst_ip'):
            for value in (alert.get('entities') or {}).get(field, []):
                if value in assets:
                    touched[value] = assets[value]
    if touched:
        name = max(touched, key=touched.get)
        points = min(settings['max_asset_points'], touched[name] * settings['points_per_asset_level'])
        components.append({'factor': 'asset_importance', 'weight': settings['max_asset_points'], 'share': None, 'points': points,
                           'reason': f'{name} has criticality level {touched[name]} in the asset list.'})
    else:
        components.append({'factor': 'asset_importance', 'weight': settings['max_asset_points'], 'share': None, 'points': 0,
                           'reason': 'No affected asset is in the asset list.'})

    subtotal = round(sum(component['points'] for component in components), 1)
    risk_score = min(100, round(subtotal))
    risk_level = risk_level_for(risk_score, settings['levels'])

    return {
        'severity': severity,
        'confidence': confidence,
        'risk_score': risk_score,
        'risk_level': risk_level,
        'score_breakdown': {
            'severity': {'value': severity, 'reason': severity_reason},
            'confidence': {
                'value': confidence,
                'method': 'Combined as 1 - product(1 - alert confidence x link score), best alert per rule.',
                'reasons': confidence_reasons,
            },
            'risk': {
                'value': risk_score,
                'level': risk_level,
                'components': components,
                'subtotal': subtotal,
                'formula': 'Each factor scores 0 to 1 and is multiplied by its weight. Asset importance is added on top. Capped at 100.',
                'note': 'Risk is an investigation priority. It is not the probability that an attack is real.',
            },
        },
    }


def tactics_in_order(alerts):
    """Distinct MITRE tactics in the order they were first observed"""
    tactics = []
    for alert in sorted(alerts, key=lambda a: a.get('first_seen_ts') or 0):
        for technique in alert.get('mitre') or []:
            if technique.get('tactic') and technique['tactic'] not in tactics:
                tactics.append(technique['tactic'])
    return tactics
