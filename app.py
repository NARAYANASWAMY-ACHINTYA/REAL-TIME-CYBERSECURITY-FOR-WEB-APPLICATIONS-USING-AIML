from http.client import HTTPException
from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for, Response, make_response, abort, flash
import sqlite3
import warnings
from datetime import datetime, timedelta
import threading
import os
import json
import time
import re
from functools import wraps, lru_cache
from feature import FeatureExtraction
from nikto_scanner import NiktoScanner
import signal
from threading import Event, Lock
from ddos_protection import ddos_protection
import logging
import logging.handlers
import sys
from flask_cors import CORS
import numpy as np
import concurrent.futures
import asyncio

# Create Flask app first
app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)

# Add request queue size limit
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB max-body-size

# Add more robust error handling
app.config['PROPAGATE_EXCEPTIONS'] = False
app.config['TRAP_HTTP_EXCEPTIONS'] = True
app.config['TRAP_BAD_REQUEST_ERRORS'] = True

# Global variables
model = None
model_lock = Lock()
model_ready = Event()
request_semaphore = threading.BoundedSemaphore(1000)  # Limit concurrent requests

# Ensure logs directory exists
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure logging with rotation
handler = logging.handlers.RotatingFileHandler(
    'logs/flask_app.log',
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# Configure CORS for extension
CORS(app, resources={
    r"/check": {
        "origins": ["chrome-extension://*"],
        "methods": ["GET"],
        "allow_headers": ["Content-Type"]
    }
})
def init_db():
    with app.app_context():
        connection = sqlite3.connect('user_data.db')
        cursor = connection.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS user(
            name TEXT, 
            password TEXT, 
            mobile TEXT, 
            email TEXT
        )""")
        connection.commit()
        connection.close()
# Initialize ML model with optimized loading
def init_model():
    global model
    try:
        with app.app_context():
            warnings.filterwarnings('ignore')
            
            # Import TensorFlow with optimized settings
            import tensorflow as tf
            
            # Configure TensorFlow for better performance
            tf.config.threading.set_inter_op_parallelism_threads(4)
            tf.config.threading.set_intra_op_parallelism_threads(4)
            
            # Enable memory growth to avoid allocating all GPU memory at once
            try:
                physical_devices = tf.config.list_physical_devices('GPU')
                for device in physical_devices:
                    tf.config.experimental.set_memory_growth(device, True)
            except:
                pass
                
            # Load model with optimized settings
            from keras.models import load_model
            with model_lock:
                # Load model with optimized settings
                model = load_model('model.h5', compile=False)
                
                # Convert to float16 for faster inference if supported
                try:
                    from tensorflow.keras.mixed_precision import set_global_policy
                    set_global_policy('mixed_float16')
                except:
                    pass
                
                # Warm up the model with dummy input (multiple batch sizes for better optimization)
                dummy_input = np.zeros((1, 30), dtype=np.float32)
                model.predict(dummy_input, verbose=0, batch_size=1)
                model.predict(np.zeros((4, 30), dtype=np.float32), verbose=0, batch_size=4)
                
            model_ready.set()
            app.logger.info("ML model initialized successfully with optimized settings")
    except Exception as e:
        app.logger.error(f"Error initializing ML model: {str(e)}")
        model_ready.set()  # Set the event even on error to prevent hanging

# Enhanced model warmup function
def warmup_model():
    """Warm up the model with a dummy prediction using various batch sizes"""
    try:
        if model_ready.is_set() and model is not None:
            # Warm up with different batch sizes for better performance
            batch_sizes = [1, 2, 4, 8]
            for batch_size in batch_sizes:
                dummy_features = np.zeros((batch_size, 30), dtype=np.float32)
                with model_lock:
                    model.predict(dummy_features, verbose=0, batch_size=batch_size)
            app.logger.info("Enhanced model warmup completed")
    except Exception as e:
        app.logger.error(f"Model warmup failed: {str(e)}")

# Initialize components after app creation
def init_app():
    # Initialize Nikto scanner
    global nikto
    nikto = NiktoScanner()
    
    # Initialize global variables
    global active_scans, scan_processes
    active_scans = {}
    scan_processes = {}
    
    # Initialize ML model in a separate thread
    model_thread = threading.Thread(target=init_model, daemon=True, name='ModelInitializer')
    model_thread.start()
    
    # Wait for model initialization and warm it up
    model_thread.join(timeout=30)  # Wait up to 30 seconds for model initialization
    if model_ready.is_set():
        warmup_model()

# Initialize everything
init_app()

# Add caching for predictions with improved TTL
prediction_cache = {}
CACHE_TTL = 86400  # 24 hours in seconds

def clean_expired_cache():
    """Remove expired items from prediction cache"""
    current_time = time.time()
    expired_keys = [k for k, v in prediction_cache.items() if current_time - v['timestamp'] > CACHE_TTL]
    for k in expired_keys:
        del prediction_cache[k]

# Create a thread pool for CPU-bound tasks
url_processing_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)

@lru_cache(maxsize=5000)  # Large cache size for better performance
async def preprocess_url(url):
    """Preprocess URL for prediction using feature extraction with balanced performance and accuracy."""
    try:
        # Normalize URL for better cache hits
        normalized_url = url.lower()
        if not normalized_url.startswith(('http://', 'https://')):
            normalized_url = 'https://' + normalized_url
        
        # Set a reasonable timeout for the entire preprocessing
        async def preprocess_with_timeout():
            # Create feature extractor with balanced timeout
            feature_extractor = FeatureExtraction(normalized_url, timeout=2.5)  # Balanced timeout
            
            # Initialize feature extractor asynchronously
            await feature_extractor.initialize()
            
            # Get features
            features = feature_extractor.getFeaturesList()
            if features is None or len(features) == 0:
                # If extraction failed, use a more balanced fallback approach
                app.logger.warning(f"Using fallback features for {normalized_url}")
                
                # Create suspicious-biased fallback features
                # This array is designed to be more balanced but lean toward detecting phishing
                # -1 values indicate potential phishing signals
                return np.array([
                    # URL-based features (more reliable for fallback)
                    1 if 'ip' not in normalized_url else -1,  # UsingIp
                    1 if len(normalized_url) < 54 else -1,    # longUrl
                    1 if not any(s in normalized_url for s in ['bit.ly', 'goo.gl', 'tinyurl']) else -1,  # shortUrl
                    1 if '@' not in normalized_url else -1,   # symbol
                    1 if normalized_url.count('//') <= 1 else -1,  # redirecting
                    1 if '-' not in normalized_url else -1,   # prefixSuffix
                    1 if normalized_url.count('.') <= 2 else -1,  # SubDomains
                    1 if normalized_url.startswith('https') else -1,  # Hppts
                    -1,  # DomainRegLen (default to suspicious)
                    -1,  # Favicon (default to suspicious)
                    
                    # Content features (default most to suspicious)
                    1,   # NonStdPort
                    1,   # HTTPSDomainURL
                    -1,  # RequestURL (default to suspicious)
                    -1,  # AnchorURL (default to suspicious)
                    -1,  # LinksInScriptTags (default to suspicious)
                    -1,  # ServerFormHandler (default to suspicious)
                    -1,  # InfoEmail (default to suspicious)
                    -1,  # AbnormalURL (default to suspicious)
                    -1,  # WebsiteForwarding (default to suspicious)
                    -1,  # StatusBarCust (default to suspicious)
                    
                    # Advanced features (default most to suspicious)
                    -1,  # DisableRightClick (default to suspicious)
                    -1,  # UsingPopupWindow (default to suspicious)
                    -1,  # IframeRedirection (default to suspicious)
                    -1,  # AgeofDomain (default to suspicious)
                    -1,  # DNSRecording (default to suspicious)
                    -1,  # WebsiteTraffic (default to suspicious)
                    -1,  # PageRank (default to suspicious)
                    -1,  # GoogleIndex (default to suspicious)
                    -1,  # LinksPointingToPage (default to suspicious)
                    -1   # StatsReport (default to suspicious)
                ], dtype=np.float32).reshape(1, -1)
            
            # Convert to numpy array efficiently
            return np.array(features, dtype=np.float32).reshape(1, -1)
        
        # Run preprocessing with a reasonable timeout
        return await asyncio.wait_for(preprocess_with_timeout(), timeout=3.0)
        
    except asyncio.TimeoutError:
        app.logger.warning(f"Preprocessing timed out for {url}, using fallback features")
        # Return fallback features that are biased toward detecting phishing
        # This is safer than assuming a site is legitimate when we couldn't analyze it
        return np.array([
            # Basic URL features (can be inferred from the URL itself)
            1 if 'ip' not in url else -1,  # UsingIp
            1 if len(url) < 54 else -1,    # longUrl
            1 if not any(s in url for s in ['bit.ly', 'goo.gl', 'tinyurl']) else -1,  # shortUrl
            1 if '@' not in url else -1,   # symbol
            1 if url.count('//') <= 1 else -1,  # redirecting
            1 if '-' not in url else -1,   # prefixSuffix
            1 if url.count('.') <= 2 else -1,  # SubDomains
            1 if url.startswith('https') else -1,  # Hppts
            # Default the rest to suspicious (-1)
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
        ], dtype=np.float32).reshape(1, -1)
    except Exception as e:
        app.logger.error(f"Error in preprocess_url for {url}: {str(e)}")
        # Return fallback features biased toward detecting phishing
        return np.array([
            # Basic URL features (can be inferred from the URL itself)
            1 if 'ip' not in url else -1,  # UsingIp
            1 if len(url) < 54 else -1,    # longUrl
            1 if not any(s in url for s in ['bit.ly', 'goo.gl', 'tinyurl']) else -1,  # shortUrl
            1 if '@' not in url else -1,   # symbol
            1 if url.count('//') <= 1 else -1,  # redirecting
            1 if '-' not in url else -1,   # prefixSuffix
            1 if url.count('.') <= 2 else -1,  # SubDomains
            1 if url.startswith('https') else -1,  # Hppts
            # Default the rest to suspicious (-1)
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
        ], dtype=np.float32).reshape(1, -1)

def get_cached_prediction(url):
    """Get prediction from cache if available"""
    if url in prediction_cache:
        cache_data = prediction_cache[url]
        if time.time() - cache_data['timestamp'] < CACHE_TTL:
            return cache_data['prediction']
    return None

def cache_prediction(url, prediction_data):
    """Cache prediction result with timestamp"""
    prediction_cache[url] = {
        'prediction': prediction_data,
        'timestamp': time.time()
    }
    # Clean expired cache entries periodically
    if len(prediction_cache) > 1000:
        clean_expired_cache()

# Prediction timeout settings - balanced for accuracy and speed
PREDICTION_TIMEOUT = 4  # seconds - balanced to ensure accuracy while meeting time limits

# Preload model with dummy data for faster first prediction
def preload_model():
    """Preload model with dummy data to optimize first prediction time"""
    if model is not None and model_ready.is_set():
        try:
            dummy_input = np.zeros((1, 30), dtype=np.float32)
            with model_lock:
                model.predict(dummy_input, verbose=0, batch_size=1)
        except Exception as e:
            app.logger.error(f"Model preloading failed: {str(e)}")

# Schedule model preloading
threading.Timer(1.0, preload_model).start()

async def predict_phishing(url):
    """Make phishing prediction using model.h5 with optimized performance."""
    start_time = time.time()
    
    try:
        # Normalize URL for better cache hits
        normalized_url = url.lower()
        if not normalized_url.startswith(('http://', 'https://')):
            normalized_url = 'https://' + normalized_url
        
        # Check cache first (using normalized URL)
        cached_result = get_cached_prediction(normalized_url)
        if cached_result:
            app.logger.info(f"Cache hit for {normalized_url}")
            return cached_result

        if not model_ready.is_set() or model is None:
            raise Exception("Model not ready")
        
        # Set a timeout for the entire prediction process
        async def prediction_with_timeout():
            # Start timing for performance monitoring
            feature_start = time.time()
            
            # Preprocess URL and get features with a very short timeout
            try:
                features = await asyncio.wait_for(preprocess_url(normalized_url), timeout=1.5)
                feature_time = time.time() - feature_start
                app.logger.info(f"Feature extraction for {normalized_url} took {feature_time:.2f}s")
            except asyncio.TimeoutError:
                app.logger.warning(f"Feature extraction timed out, using fallback features")
                # Use fallback features if extraction times out
                features = np.array([1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 
                                    0, 0, 0, 0, 0, 0, 0, 1, 0, 1], dtype=np.float32).reshape(1, -1)
            
            # Start timing model prediction
            model_start = time.time()
            
            # Use a thread pool for model prediction to avoid blocking the event loop
            loop = asyncio.get_event_loop()
            
            def predict_with_model():
                with model_lock:
                    # Use a very small batch size for faster prediction
                    return model.predict(features, verbose=0, batch_size=1)
            
            # Run model prediction in thread pool with a reasonable timeout
            try:
                prediction = await asyncio.wait_for(
                    loop.run_in_executor(None, predict_with_model), 
                    timeout=1.0  # Reasonable timeout for model prediction
                )
                model_time = time.time() - model_start
                app.logger.info(f"Model prediction for {normalized_url} took {model_time:.2f}s")
            except asyncio.TimeoutError:
                app.logger.warning(f"Model prediction timed out, using fallback prediction")
                # If model prediction times out, return a suspicious fallback
                # It's safer to flag a site as potentially suspicious if we couldn't analyze it properly
                return (False, 0.7, 0.3)  # Default to suspicious with moderate confidence
            
            if prediction is None or len(prediction) == 0:
                app.logger.warning(f"Model returned no prediction, using fallback")
                return (True, 0.1, 0.9)  # Default to safe with high confidence
                
            # Process prediction results
            probability_non_phishing = float(prediction[0][0])
            probability_phishing = 1 - probability_non_phishing
            prediction_binary = bool(np.round(prediction)[0][0])
            
            return (prediction_binary, probability_phishing, probability_non_phishing)
        
        # Run the entire prediction process with a balanced timeout
        try:
            result = await asyncio.wait_for(prediction_with_timeout(), timeout=PREDICTION_TIMEOUT)
        except asyncio.TimeoutError:
            app.logger.warning(f"Complete prediction process timed out, using fallback")
            
            # If the entire process times out, analyze the URL for suspicious patterns
            # This provides a more intelligent fallback than a fixed response
            suspicious_patterns = [
                '.php?', 'login', 'signin', 'account', 'secure', 'update', 'banking',
                'confirm', 'verify', 'password', 'credential', 'wallet', 'payment',
                'paypal', 'apple', 'microsoft', 'amazon', 'netflix', 'facebook',
                'google', 'instagram', 'twitter', 'bank', 'ebay', 'verify', 'secure'
            ]
            
            # Check if URL contains suspicious patterns
            contains_suspicious = any(pattern in normalized_url.lower() for pattern in suspicious_patterns)
            
            # Check for other suspicious indicators
            has_ip = bool(re.search(r'\d+\.\d+\.\d+\.\d+', normalized_url))
            has_many_dots = normalized_url.count('.') > 3
            is_very_long = len(normalized_url) > 100
            has_suspicious_tld = any(normalized_url.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.cf', '.gq'])
            
            # Calculate suspicion score
            suspicion_factors = [contains_suspicious, has_ip, has_many_dots, is_very_long, has_suspicious_tld]
            suspicion_score = sum(1 for factor in suspicion_factors if factor) / len(suspicion_factors)
            
            # Determine result based on suspicion score
            if suspicion_score > 0.3:  # If more than 30% of factors are suspicious
                result = (False, 0.5 + suspicion_score * 0.3, 0.5 - suspicion_score * 0.3)  # Suspicious with confidence based on score
            else:
                result = (True, 0.3, 0.7)  # Likely safe but with moderate confidence
        
        # Cache the result (using normalized URL)
        cache_prediction(normalized_url, result)
        
        # Log performance metrics
        elapsed_time = time.time() - start_time
        app.logger.info(f"Prediction for {normalized_url} completed in {elapsed_time:.2f}s")
        
        return result
        
    except asyncio.TimeoutError:
        app.logger.error(f"Prediction timed out for URL {url} after {PREDICTION_TIMEOUT}s")
        raise Exception(f"Prediction timed out after {PREDICTION_TIMEOUT} seconds")
    except Exception as e:
        elapsed_time = time.time() - start_time
        app.logger.error(f"Prediction failed for URL {url} after {elapsed_time:.2f}s: {str(e)}")
        raise Exception(f"Prediction failed: {str(e)}")

@app.route('/check')
def check_url():
    """Endpoint for checking URLs - optimized for speed"""
    url = request.args.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    try:
        # Create an event loop for async operations
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Run the async function in the event loop
            prediction_binary, probability_phishing, probability_safe = loop.run_until_complete(predict_phishing(url))
        finally:
            loop.close()
        
        return jsonify({
            'is_phishing': not prediction_binary,  # Invert because 1 means safe in our model
            'probability_phishing': float(probability_phishing),
            'probability_safe': float(probability_safe)
        })
    except Exception as e:
        app.logger.error(f"Error checking URL {url}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/ANN', methods=['GET', 'POST'])
def ANN():
    if request.method == 'GET':
        res = session.pop('url_analysis_result', None)
        url = session.pop('analyzed_url', None)
        loading = session.pop('loading', False)
        return render_template('ann.html', res=res, url=url, loading=loading)
    
    Link = request.form['Link']
    try:
        # Validate URL format
        if not Link.startswith(('http://', 'https://')):
            Link = 'https://' + Link
            
        # Set loading state
        session['loading'] = True
        session['analyzed_url'] = Link
        
        # Check cache first
        cached_result = get_cached_prediction(Link)
        if cached_result:
            prediction_binary, probability_phishing, probability_non_phishing = cached_result
        else:
            # Create an event loop for async operations
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                # Run the async function in the event loop with a timeout
                prediction_binary, probability_phishing, probability_non_phishing = loop.run_until_complete(
                    asyncio.wait_for(
                        predict_phishing(Link), 
                        timeout=10
                    )
                )
            except asyncio.TimeoutError:
                session['loading'] = False
                return render_template('ann.html', error="Analysis timed out. Please try again.", url=Link)
            finally:
                loop.close()

        # Format probabilities as percentages
        probability_phishing_percentage = probability_phishing * 100
        probability_non_phishing_percentage = probability_non_phishing * 100

        # Generate result message based on model prediction
        if not prediction_binary:  # Invert because 1 means safe in our model
            res = f"⚠️ WARNING: The URL is {probability_phishing_percentage:.1f}% likely to be UNSAFE"
        else:
            res = f"✅ The URL is {probability_non_phishing_percentage:.1f}% likely to be SAFE"
            
        # Store result in session
        session['url_analysis_result'] = res
        session['loading'] = False
        
        return redirect(url_for('ANN'))
        
    except Exception as e:
        error_message = f"Error analyzing URL: {str(e)}"
        app.logger.error(error_message)
        session['loading'] = False
        session['url_analysis_result'] = f"Error: {error_message}"
        return redirect(url_for('ANN'))

@app.route('/')
def home():
        return render_template('index.html')

@app.route('/project')
def project():
    return render_template('project.html')

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/extension')
def extension():
    return render_template('extension.html')

@app.route('/extension/stats')
def extension_stats():
    """Get current extension statistics"""
    try:
        with sqlite3.connect('extension_stats.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT total_scans, threats_detected, last_scan FROM extension_stats WHERE id = 1")
            stats = cursor.fetchone()
            
            if stats:
                return jsonify({
                    'total_scans': stats[0],
                    'threats_detected': stats[1],
                    'last_scan': stats[2],
                    'status': 'success'
                })
            return jsonify({
                'total_scans': 0,
                'threats_detected': 0,
                'last_scan': None,
                'status': 'success'
            })
    except Exception as e:
        app.logger.error(f"Error getting extension stats: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/check', methods=['GET'])
def check_url_endpoint():
    """Check a URL for phishing and update statistics"""
    try:
        url = request.args.get('url')
        if not url:
            return jsonify({'error': 'URL is required'}), 400

        # Create an event loop for async operations
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Run the async function in the event loop
            prediction_binary, probability_phishing, probability_safe = loop.run_until_complete(predict_phishing(url))
            
            # Update statistics
            is_phishing = probability_phishing > 0.5
            with sqlite3.connect('extension_stats.db') as conn:
                cursor = conn.cursor()
                now = datetime.now().isoformat()
                cursor.execute("""
                    UPDATE extension_stats 
                    SET total_scans = total_scans + 1,
                        threats_detected = threats_detected + ?,
                        last_scan = ?,
                        last_update = ?
                    WHERE id = 1
                """, (1 if is_phishing else 0, now, now))
                conn.commit()
            
            response = {
                'is_phishing': is_phishing,
                'confidence': float(max(probability_phishing, probability_safe)),
                'probability_phishing': float(probability_phishing),
                'probability_safe': float(probability_safe)
            }
            
            return jsonify(response)
            
        finally:
            loop.close()
            
    except Exception as e:
        app.logger.error(f"Error checking URL: {str(e)}")
        return jsonify({'error': str(e)}), 500

def limit_request_size():
    """Limit request size to prevent memory exhaustion."""
    if request.content_length and request.content_length > app.config['MAX_CONTENT_LENGTH']:
        abort(413)  # Request Entity Too Large

def acquire_request_slot():
    """Acquire a slot in the request semaphore with timeout."""
    if not request_semaphore.acquire(timeout=5):  # 5 seconds timeout
        abort(503)  # Service Unavailable

def release_request_slot():
    """Release the request slot."""
    try:
        request_semaphore.release()
    except ValueError:
        pass  # Ignore if already released

@app.before_request
def before_request():
    """Handle pre-request checks."""
    try:
        # Skip checks for static files
        if request.path.startswith('/static/'):
            return
            
        # Limit request size
        limit_request_size()
        
        # Acquire request slot
        acquire_request_slot()
        
        # Check for DDoS
        if not request.path.startswith(('/static/', '/favicon.ico', '/ddos/stats')):
            if not ddos_protection.check_http_flood(request.remote_addr):
                app.logger.warning(f"Blocked request from {request.remote_addr} - potential DDoS attack")
                abort(429, "Too Many Requests")
                
    except Exception as e:
        app.logger.error(f"Error in before_request: {str(e)}")
        abort(500)

@app.after_request
def after_request(response):
    """Handle post-request cleanup."""
    try:
        # Release request slot
        release_request_slot()
        
        # Add security headers
        response.headers.update({
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Server': 'Protected Server'  # Hide real server details
        })
        
        if request.path == '/ddos/stats':
            response.headers.update({
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET',
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            })
        
        if ddos_protection.under_attack:
            response.headers.update({
                'X-Under-Attack': 'True',
                'X-Attack-Type': ddos_protection.attack_type
            })
            
        return response
        
    except Exception as e:
        app.logger.error(f"Error in after_request: {str(e)}")
        return response

@app.errorhandler(Exception)
def handle_error(e):
    """Global error handler."""
    try:
        # Release request slot on error
        release_request_slot()
        
        if isinstance(e, HTTPException):
            return jsonify({
                'status': 'error',
                'code': e.code,
                'message': e.description
            }), e.code
            
        app.logger.error(f"Unhandled error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500
        
    except Exception as e2:
        app.logger.error(f"Error in error handler: {str(e2)}")
        return 'Internal server error', 500

@app.route('/ddos')
def ddos_page():
    """Render the DDoS protection dashboard."""
    try:
        stats = get_cached_ddos_stats()
        return render_template('DDoS.html', stats=stats)
    except Exception as e:
        app.logger.error(f"Error rendering DDoS page: {str(e)}")
        return render_template('DDoS.html', stats={
            'protection_enabled': True,
            'under_attack': False,
            'tracked_ips': 0,
            'blocked_ips': 0,
            'half_open_connections': 0,
            'blacklisted_ips': []
        })

@app.route('/ddos/toggle', methods=['POST'])
def toggle_ddos_protection():
    """Toggle DDoS protection status with enhanced error handling."""
    try:
        # Toggle protection state
        new_state = ddos_protection.toggle_protection()
        
        # Get updated stats
        stats = ddos_protection.get_protection_stats()
        
        # Clear stats cache to ensure fresh data
        get_cached_ddos_stats.cache_clear()
        
        return jsonify({
            'status': 'success',
            'enabled': new_state,
            'message': f"DDoS protection {'enabled' if new_state else 'disabled'}",
            'stats': stats
        })
    except Exception as e:
        app.logger.error(f"Error toggling DDoS protection: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to update protection status',
            'error': str(e)
        }), 500

@app.route('/ddos/stats')
def get_ddos_stats():
    """Get current DDoS protection statistics with caching."""
    try:
        stats = ddos_protection.get_protection_stats()
        return jsonify({
            'status': 'success',
            'stats': stats,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        app.logger.error(f"Error getting DDoS stats: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve protection statistics',
            'error': str(e)
        }), 500

@app.route('/vulnerability')
def vulnerability():
    """Render the vulnerability scanner page."""
    return render_template('vulnerability.html')

@app.route('/vulnerability/stop', methods=['POST'])
def stop_vulnerability_scan():
    """Stop an active vulnerability scan."""
    try:
        scan_id = request.form.get('scan_id')
        if scan_id in scan_processes:
            process = scan_processes[scan_id]
            if process:
                # Send SIGTERM to the process group
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                # Clean up
                del scan_processes[scan_id]
                if scan_id in active_scans:
                    active_scans[scan_id].set()
                    del active_scans[scan_id]
            return jsonify({'status': 'success', 'message': 'Scan stopped successfully'})
        return jsonify({'status': 'error', 'message': 'Scan not found'}), 404
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/vulnerability/scan', methods=['GET', 'POST'])
def start_vulnerability_scan():
    """Start a vulnerability scan and stream the results."""
    try:
        # Get target URL from various sources
        target_url = None
        
        if request.method == 'POST':
            data = request.get_json()
            if data:
                target_url = data.get('target_url')
        
        if not target_url:
            target_url = request.args.get('target_url')

        if not target_url:
            return jsonify({'error': 'Target URL is required'}), 400

        # Generate a unique scan ID
        scan_id = str(hash(f"{target_url}_{datetime.now().timestamp()}"))
        
        # Create an event for this scan
        scan_event = Event()
        active_scans[scan_id] = scan_event

        # Initialize scanner
        scanner = NiktoScanner()

        def generate():
            vulnerabilities = []
            secure_findings = []
            info_findings = []
            error_findings = []
            
            stats = {
                'high_risk': 0,
                'medium_risk': 0,
                'low_risk': 0,
                'total_cvss': 0,
                'average_cvss': 0,
                'scan_start': datetime.now().isoformat(),
                'scan_end': None,
                'total_tests': 0,
                'completed_tests': 0,
                'progress': 0,
                'secure_components': 0,
                'info_messages': 0,
                'errors': 0
            }
            
            try:
                # Send initial status
                yield f"data: {json.dumps({'type': 'log', 'data': 'Starting comprehensive security scan...', 'scan_id': scan_id})}\n\n"
                
                # Start the scan with a timeout
                for output in scanner.scan(target_url, timeout=300):
                    # Check if scan was stopped
                    if scan_event.is_set():
                        yield f"data: {json.dumps({'type': 'log', 'data': 'Scan stopped by user', 'scan_id': scan_id})}\n\n"
                        break
                    
                    if isinstance(output, dict):
                        if output.get('type') == 'progress':
                            # Update progress information
                            stats['progress'] = output['percentage']
                            stats['completed_tests'] = output['completed']
                            stats['total_tests'] = output['total']
                            yield f"data: {json.dumps({'type': 'progress', 'data': stats, 'scan_id': scan_id})}\n\n"
                        elif output.get('type') == 'summary':
                            # Handle summary data
                            summary = output['data']
                            stats.update({
                                'secure_components': summary['secure_components'],
                                'info_messages': summary['info_messages'],
                                'errors': summary['errors']
                            })
                            yield f"data: {json.dumps({'type': 'summary', 'data': summary, 'scan_id': scan_id})}\n\n"
                        else:
                            # This is a finding
                            status = output.get('status', 'info')
                            if status == 'vulnerable':
                                vulnerabilities.append(output)
                                risk_level = output.get('risk_level', 'low')
                                stats[f"{risk_level}_risk"] += 1
                                stats['total_cvss'] += output.get('cvss_score', 0)
                            elif status == 'secure':
                                secure_findings.append(output)
                            elif status == 'info':
                                info_findings.append(output)
                            elif status == 'error':
                                error_findings.append(output)
                            
                            yield f"data: {json.dumps({'type': 'finding', 'data': output, 'scan_id': scan_id})}\n\n"
                    elif isinstance(output, str):
                        # This is a log message
                        yield f"data: {json.dumps({'type': 'log', 'data': output, 'scan_id': scan_id})}\n\n"
                
                # Calculate final statistics
                stats['scan_end'] = datetime.now().isoformat()
                total_findings = len(vulnerabilities)
                if total_findings > 0:
                    stats['average_cvss'] = stats['total_cvss'] / total_findings
                
                # Prepare recommendations based on findings
                recommendations = []
                
                if vulnerabilities:
                    recommendations.extend([
                        {
                            'priority': 'Critical',
                            'items': [v for v in vulnerabilities if v.get('risk_level') == 'high']
                        },
                        {
                            'priority': 'Important',
                            'items': [v for v in vulnerabilities if v.get('risk_level') == 'medium']
                        },
                        {
                            'priority': 'Low',
                            'items': [v for v in vulnerabilities if v.get('risk_level') == 'low']
                        }
                    ])
                
                if secure_findings:
                    recommendations.append({
                        'priority': 'Secure',
                        'items': secure_findings,
                        'message': 'These components meet security standards'
                    })
                
                if info_findings:
                    recommendations.append({
                        'priority': 'Information',
                        'items': info_findings,
                        'message': 'Additional security information and suggestions'
                    })
                
                if error_findings:
                    recommendations.append({
                        'priority': 'Errors',
                        'items': error_findings,
                        'message': 'Issues encountered during scanning'
                    })
                
                # Send final report
                final_report = {
                    'statistics': stats,
                    'vulnerabilities': vulnerabilities,
                    'secure_findings': secure_findings,
                    'info_findings': info_findings,
                    'error_findings': error_findings,
                    'recommendations': recommendations,
                    'scan_summary': {
                        'total_tests_run': stats['total_tests'],
                        'vulnerabilities_found': len(vulnerabilities),
                        'secure_components': len(secure_findings),
                        'info_messages': len(info_findings),
                        'errors': len(error_findings),
                        'overall_security_status': 'Vulnerable' if vulnerabilities else 'Secure' if secure_findings else 'Unknown'
                    },
                    'scan_id': scan_id,
                    'scan_time': datetime.now().isoformat()  # Add scan time in ISO format
                }
                
                yield f"data: {json.dumps({'type': 'report', 'data': final_report})}\n\n"
                
            except Exception as e:
                app.logger.error(f"Scan error for {target_url}: {str(e)}")
                yield f"data: {json.dumps({'type': 'error', 'data': str(e), 'scan_id': scan_id})}\n\n"
            finally:
                # Ensure cleanup happens
                try:
                    if scan_id in scan_processes:
                        process = scan_processes[scan_id]
                        if process and process.poll() is None:
                            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                        del scan_processes[scan_id]
                    if scan_id in active_scans:
                        del active_scans[scan_id]
                except Exception as cleanup_error:
                    app.logger.error(f"Cleanup error for scan {scan_id}: {str(cleanup_error)}")

        return Response(
            generate(),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'X-Accel-Buffering': 'no'
            }
        )
    except Exception as e:
        app.logger.error(f"Error starting vulnerability scan: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Cache for DDoS stats to prevent frequent database hits
@lru_cache(maxsize=1)
def get_cached_ddos_stats():
    """Get cached DDoS protection statistics."""
    return ddos_protection.get_protection_stats()

# Clear stats cache periodically
def clear_stats_cache():
    """Clear the DDoS stats cache periodically."""
    while True:
        time.sleep(1)  # Clear cache every second
        get_cached_ddos_stats.cache_clear()

# Start cache clearing thread
threading.Thread(target=clear_stats_cache, daemon=True, name='StatsCacheCleaner').start()

# Add application start time tracking
app.start_time = time.time()

@app.route('/logs')
def view_logs():
    return render_template('logs.html')

@app.route('/settings')
def manage_settings():
    return render_template('settings.html')

@app.route('/scan')
def run_scan():
    return render_template('scan.html')

@app.route('/reports')
def view_reports():
    return render_template('reports.html')

@app.route('/ddos')
def manage_ddos():
    return render_template('ddos.html')

@app.route('/alerts')
def view_alerts():
    return render_template('alerts.html')

# Add context processor for template access to permissions

# Main routes

@app.route('/ann', methods=['GET', 'POST'])
def ann_redirect():
    if request.method == 'POST':
        return redirect(url_for('ANN'), code=307)  # 307 preserves the POST method
    return redirect(url_for('ANN'))

if __name__ == '__main__':

        print("Starting the application...")
        print("Access the application at: http://127.0.0.1:5000")
        
        # Run with optimized settings
        app.run(
            host='127.0.0.1',
            port=5000,
            debug=False,  # Disable debug mode in production
            threaded=True,
            processes=1  # Use threading model for better control
        )

