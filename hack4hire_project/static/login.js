/**
 * Analyst Portal Authentication & Registration Controller
 * Connects to /api/auth/login and /api/auth/register
 */

const errorNotice = document.getElementById('login-error');
const successNotice = document.getElementById('login-success');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const tabBtnLogin = document.getElementById('tab-btn-login');
const tabBtnRegister = document.getElementById('tab-btn-register');
const demoLoginBtn = document.getElementById('demo-login-btn');

function hideNotices() {
    if (errorNotice) errorNotice.hidden = true;
    if (successNotice) successNotice.hidden = true;
}

function switchTab(target) {
    hideNotices();
    if (target === 'register') {
        tabBtnRegister.classList.add('active');
        tabBtnRegister.setAttribute('aria-selected', 'true');
        tabBtnLogin.classList.remove('active');
        tabBtnLogin.setAttribute('aria-selected', 'false');
        loginForm.hidden = true;
        registerForm.hidden = false;
        registerForm.elements.reg_username.focus();
    } else {
        tabBtnLogin.classList.add('active');
        tabBtnLogin.setAttribute('aria-selected', 'true');
        tabBtnRegister.classList.remove('active');
        tabBtnRegister.setAttribute('aria-selected', 'false');
        registerForm.hidden = true;
        loginForm.hidden = false;
        loginForm.elements.username.focus();
    }
}

tabBtnLogin?.addEventListener('click', () => switchTab('login'));
tabBtnRegister?.addEventListener('click', () => switchTab('register'));

// Sign In Form Submission
loginForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.target;
    const submitBtn = form.querySelector('button[type="submit"]');
    hideNotices();
    submitBtn.disabled = true;

    try {
        const username = form.elements.username.value.trim();
        const password = form.elements.password.value;
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
        });

        if (response.ok) {
            successNotice.textContent = `Welcome back, ${username}! Redirecting to SOC Command Center...`;
            successNotice.hidden = false;
            setTimeout(() => {
                window.location.assign('/dashboard');
            }, 600);
            return;
        }

        const body = await response.json().catch(() => ({}));
        errorNotice.textContent = body.error || 'Could not sign in with provided credentials.';
        errorNotice.hidden = false;
    } catch (e) {
        errorNotice.textContent = 'The security gateway server could not be reached.';
        errorNotice.hidden = false;
    } finally {
        submitBtn.disabled = false;
    }
});

// Register Form Submission
registerForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.target;
    const submitBtn = form.querySelector('button[type="submit"]');
    hideNotices();

    const username = form.elements.reg_username.value.trim();
    const role = form.elements.reg_role.value;
    const password = form.elements.reg_password.value;
    const confirm = form.elements.reg_confirm.value;

    if (password !== confirm) {
        errorNotice.textContent = 'Passwords do not match.';
        errorNotice.hidden = false;
        return;
    }

    if (password.length < 10) {
        errorNotice.textContent = 'Password must have at least 10 characters.';
        errorNotice.hidden = false;
        return;
    }

    submitBtn.disabled = true;
    try {
        const response = await fetch('/api/auth/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, role }),
        });

        if (response.ok) {
            const created = await response.json().catch(() => ({}));
            const grantedRole = created.user ? created.user.role : role;
            successNotice.textContent = grantedRole === role
                ? `Account created for ${username} as ${grantedRole}. Starting your session...`
                : `Account created for ${username} as ${grantedRole}: only an analyst can create another analyst. Starting your session...`;
            successNotice.hidden = false;
            setTimeout(() => {
                window.location.assign('/dashboard');
            }, 800);
            return;
        }

        const body = await response.json().catch(() => ({}));
        errorNotice.textContent = body.error || 'Could not register new account.';
        errorNotice.hidden = false;
    } catch (e) {
        errorNotice.textContent = 'Registration service unavailable.';
        errorNotice.hidden = false;
    } finally {
        submitBtn.disabled = false;
    }
});

// 1-Click Instant Demo Login
demoLoginBtn?.addEventListener('click', async () => {
    hideNotices();
    demoLoginBtn.disabled = true;
    demoLoginBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Authenticating Demo Analyst...';

    try {
        const response = await fetch('/api/auth/demo', { method: 'POST' });

        if (response.ok) {
            successNotice.textContent = 'Signed in as the demo analyst. Opening the console...';
            successNotice.hidden = false;
            setTimeout(() => {
                window.location.assign('/dashboard');
            }, 500);
            return;
        }

        const body = await response.json().catch(() => ({}));
        errorNotice.textContent = body.error || 'Demo sign in failed.';
        errorNotice.hidden = false;
    } catch (e) {
        errorNotice.textContent = 'The security gateway server could not be reached.';
        errorNotice.hidden = false;
    } finally {
        demoLoginBtn.disabled = false;
        demoLoginBtn.innerHTML = '<i class="fa-solid fa-user-check"></i> 1-Click Demo Analyst Sign In';
    }
});
