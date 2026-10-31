9877import hashlib
import json
import logging
import math
import os
import re
import threading
import warnings

from models import insert_ml_predictions
from utils.detection_engine import simulation_run_of

logger = logging.getLogger(__name__)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(ROOT, 'nids_model.pkl')
ENCODER_PATH = os.path.join(ROOT, 'label_encoder.pkl')
RULES_PATH = os.path.join(ROOT, 'config', 'ml_rules.json')

BENIGN = 'BENIGN'
UNCALIBRATED_NOTE = 'The model has not been calibrated, so no prediction confidence is reported.'

# The 78 CIC-IDS2017 flow features the saved model was trained on, in its order
FLOW_FEATURES = (
    'Destination_Port', 'Flow_Duration', 'Total_Fwd_Packets', 'Total_Backward_Packets', 'Total_Length_of_Fwd_Packets',
    'Total_Length_of_Bwd_Packets', 'Fwd_Packet_Length_Max', 'Fwd_Packet_Length_Min', 'Fwd_Packet_Length_Mean',
    'Fwd_Packet_Length_Std', 'Bwd_Packet_Length_Max', 'Bwd_Packet_Length_Min', 'Bwd_Packet_Length_Mean',
    'Bwd_Packet_Length_Std', 'Flow_Bytes/s', 'Flow_Packets/s', 'Flow_IAT_Mean', 'Flow_IAT_Std', 'Flow_IAT_Max',
    'Flow_IAT_Min', 'Fwd_IAT_Total', 'Fwd_IAT_Mean', 'Fwd_IAT_Std', 'Fwd_IAT_Max', 'Fwd_IAT_Min', 'Bwd_IAT_Total',
    'Bwd_IAT_Mean', 'Bwd_IAT_Std', 'Bwd_IAT_Max', 'Bwd_IAT_Min', 'Fwd_PSH_Flags', 'Bwd_PSH_Flags', 'Fwd_URG_Flags',
    'Bwd_URG_Flags', 'Fwd_Header_Length', 'Bwd_Header_Length', 'Fwd_Packets/s', 'Bwd_Packets/s', 'Min_Packet_Length',
    'Max_Packet_Length', 'Packet_Length_Mean', 'Packet_Length_Std', 'Packet_Length_Variance', 'FIN_Flag_Count',
    'SYN_Flag_Count', 'RST_Flag_Count', 'PSH_Flag_Count', 'ACK_Flag_Count', 'URG_Flag_Count', 'CWE_Flag_Count',
    'ECE_Flag_Count', 'Down/Up_Ratio', 'Average_Packet_Size', 'Avg_Fwd_Segment_Size', 'Avg_Bwd_Segment_Size',
    'Fwd_Header_Length.1', 'Fwd_Avg_Bytes/Bulk', 'Fwd_Avg_Packets/Bulk', 'Fwd_Avg_Bulk_Rate', 'Bwd_Avg_Bytes/Bulk',
    'Bwd_Avg_Packets/Bulk', 'Bwd_Avg_Bulk_Rate', 'Subflow_Fwd_Packets', 'Subflow_Fwd_Bytes', 'Subflow_Bwd_Packets',
    'Subflow_Bwd_Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
    'Active_Mean', 'Active_Std', 'Active_Max', 'Active_Min', 'Idle_Mean', 'Idle_Std', 'Idle_Max', 'Idle_Min',
)
FLOW_FEATURE_SET = set(FLOW_FEATURES)


def flow_key(name):
    """CIC-IDS2017 files write ' Flow Duration'. The model calls it 'Flow_Duration'."""
    return re.sub(r'\s+', '_', str(name).strip())


def _number(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return float('nan')
    return number if math.isfinite(number) else float('nan')


def feature_row(record):
    """The record's 78 features in the model's order, or None if any column is absent.
    CIC-IDS2017 has two identical 'Fwd Header Length' columns, and a CSV reader keeps one."""
    flat = {flow_key(key): value for key, value in record.items()}
    if 'Fwd_Header_Length.1' not in flat and 'Fwd_Header_Length' in flat:
        flat['Fwd_Header_Length.1'] = flat['Fwd_Header_Length']
    if not FLOW_FEATURE_SET <= set(flat):
        return None
    return [_number(flat[name]) for name in FLOW_FEATURES]


def missing_features(record):
    flat = {flow_key(key) for key in record}
    if 'Fwd_Header_Length' in flat:
        flat.add('Fwd_Header_Length.1')
    return sorted(FLOW_FEATURE_SET - flat)


def is_flow_event(event):
    """True only for records the dataset parser confirmed carry every model feature"""
    fields = event.get('normalized_fields')
    return bool(fields) and '"model_features": true' in fields


def load_ml_rules(path=RULES_PATH):
    with open(path, encoding='utf-8') as handle:
        return json.load(handle)['rules']


class NidsEngine:
    """The saved network model, used only on records carrying its real input features.

    It is a soft vote of LightGBM, XGBoost and CatBoost. Windows, Linux and application logs are
    never fed to it, because padding or guessing features makes its output meaningless. No
    preprocessing pipeline was saved with it, and its tree models take the features as they are.
    """

    def __init__(self, model_path=MODEL_PATH, encoder_path=ENCODER_PATH, enabled=None):
        if not os.path.exists(model_path) and os.path.exists(model_path + '.gz'):
            model_path = model_path + '.gz'
        self.model_path = model_path
        self.encoder_path = encoder_path
        self.enabled = os.environ.get('ALLSAFE_LOAD_ML', '1') == '1' if enabled is None else enabled
        self.rules = {name: rule for rule in load_ml_rules() for name in rule['classes']}
        self._model = None
        self._classes = None
        self._failure = None
        self._lock = threading.Lock()
        self.version = None
        self.last_detail = {}

    def _load(self):
        with self._lock:
            if self._model is not None:
                return True
            if self._failure:
                return False
            if not self.enabled:
                self._failure = 'The saved model is switched off by configuration (ALLSAFE_LOAD_ML=0).'
                return False
            if not (os.path.exists(self.model_path) and os.path.exists(self.encoder_path)):
                self._failure = 'The saved model files are not present.'
                return False
            try:
                import joblib
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    model = joblib.load(self.model_path)
                    encoder = joblib.load(self.encoder_path)
                names = next((tuple(str(n) for n in sub.feature_names_in_) for sub in model.estimators_ if hasattr(sub, 'feature_names_in_')), None)
                if names != FLOW_FEATURES:
                    self._failure = 'The saved model does not use the expected 78 flow features.'
                    return False
                # The bundled encoder holds a mis-decoded dash in the web attack class names
                self._classes = [str(name).replace('�', '-') for name in encoder.classes_]
                with open(self.model_path, 'rb') as handle:
                    self.version = hashlib.sha256(handle.read()).hexdigest()[:12]
                self._model = model
                return True
            except Exception as error:
                logger.exception('Could not load the saved network model')
                self._failure = f'The saved model could not be loaded ({type(error).__name__}).'
                return False

    def status(self):
        """What can be said without loading the model, which takes a few seconds"""
        if not self.enabled:
            available, reason = False, 'Switched off by configuration (ALLSAFE_LOAD_ML=0).'
        elif self._failure:
            available, reason = False, self._failure
        elif not os.path.exists(self.model_path):
            available, reason = False, 'The saved model files are not present.'
        else:
            available, reason = True, None
        return {
            'name': 'Saved network model (soft vote of LightGBM, XGBoost and CatBoost)',
            'available': available,
            'reason': reason,
            'loaded': self._model is not None,
            'version': self.version,
            'classes': self._classes,
            'input': f'{len(FLOW_FEATURES)} CIC-IDS2017 flow features',
            'calibrated': False,
            'validated': False,
            'note': 'Used only on flow data with all of its features. Not validated here, so no accuracy is claimed. ' + UNCALIBRATED_NOTE,
        }

    def predict(self, rows):
        """Class names for feature rows. Raises if the model cannot run, so the failure is seen."""
        if not self._load():
            raise RuntimeError(self._failure)
        import numpy as np
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            predicted = self._model.predict(np.array(rows, dtype=float))
        return [self._classes[int(index)] for index in np.ravel(predicted)]

    def evaluate(self, events):
        """Classify the flows among these events and store every prediction. Returns findings
        for flows with a timestamp that were classified as attacks."""
        self.last_detail = {}
        flows = [event for event in events if is_flow_event(event)]
        if not flows:
            return []
        if not self._load():
            self.last_detail = {'reason': self._failure}
            return []

        usable, rows = [], []
        for event in flows:
            row = feature_row(json.loads(event['raw_event']))
            if row is not None:
                usable.append(event)
                rows.append(row)
        labels = self.predict(rows) if rows else []
        insert_ml_predictions([(event['id'], event.get('ingest_batch'), event.get('event_id'), label, self.version)
                               for event, label in zip(usable, labels)])
        self.last_detail = {'model_version': self.version, 'calibrated': False}

        groups = {}
        for event, label in zip(usable, labels):
            if label == BENIGN or event.get('ts_epoch') is None:
                continue
            key = (label, event.get('src_ip'), event.get('dst_ip'), simulation_run_of(event))
            groups.setdefault(key, []).append(event)
        return [self._finding(key, members) for key, members in groups.items()]

    def _finding(self, key, events):
        label, src_ip, dst_ip, run = key
        events.sort(key=lambda e: (e['ts_epoch'], e['id']))
        group = {'predicted_class': label, 'src_ip': src_ip, 'dst_ip': dst_ip}
        if run:
            group['simulation_run'] = run
        rule = self.rules.get(label) or self.rules['*']
        return {
            'rule': rule,
            'group': group,
            'events': events,
            'observed': len(events),
            'first_ts': events[0]['ts_epoch'],
            'last_ts': events[-1]['ts_epoch'],
            'metrics': {'predicted_class': label},
            'extra_evidence': {'predicted_class': label, 'model_version': self.version, 'calibrated': False},
        }
