from flask import jsonify, render_template
from werkzeug.exceptions import HTTPException
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LoopDetected(HTTPException):
    code = 508
    description = 'Loop Detected'

class PaymentRequired(HTTPException):
    code = 402
    description = 'Payment Required'

def register_error_handlers(app):
    """Register error handlers for the Flask application"""
    
    @app.errorhandler(400)
    def bad_request_error(error):
        logger.error(f"Bad Request: {str(error)}")
        return jsonify({
            'error': 'Bad Request',
            'message': str(error),
            'status_code': 400
        }), 400

    @app.errorhandler(401)
    def unauthorized_error(error):
        logger.error(f"Unauthorized: {str(error)}")
        return jsonify({
            'error': 'Unauthorized',
            'message': str(error),
            'status_code': 401
        }), 401

    @app.errorhandler(PaymentRequired)
    def payment_required_error(error):
        logger.error(f"Payment Required: {str(error)}")
        return jsonify({
            'error': 'Payment Required',
            'message': str(error),
            'status_code': 402
        }), 402

    @app.errorhandler(403)
    def forbidden_error(error):
        logger.error(f"Forbidden: {str(error)}")
        return jsonify({
            'error': 'Forbidden',
            'message': str(error),
            'status_code': 403
        }), 403

    @app.errorhandler(404)
    def not_found_error(error):
        logger.error(f"Not Found: {str(error)}")
        return jsonify({
            'error': 'Not Found',
            'message': str(error),
            'status_code': 404
        }), 404

    @app.errorhandler(405)
    def method_not_allowed_error(error):
        logger.error(f"Method Not Allowed: {str(error)}")
        return jsonify({
            'error': 'Method Not Allowed',
            'message': str(error),
            'status_code': 405
        }), 405

    @app.errorhandler(413)
    def payload_too_large_error(error):
        logger.error(f"Payload Too Large: {str(error)}")
        return jsonify({
            'error': 'Payload Too Large',
            'message': str(error),
            'status_code': 413
        }), 413

    @app.errorhandler(414)
    def url_too_long_error(error):
        logger.error(f"URL Too Long: {str(error)}")
        return jsonify({
            'error': 'URL Too Long',
            'message': str(error),
            'status_code': 414
        }), 414

    @app.errorhandler(431)
    def header_too_large_error(error):
        logger.error(f"Header Too Large: {str(error)}")
        return jsonify({
            'error': 'Header Too Large',
            'message': str(error),
            'status_code': 431
        }), 431

    @app.errorhandler(500)
    def internal_server_error(error):
        logger.error(f"Internal Server Error: {str(error)}")
        return jsonify({
            'error': 'Internal Server Error',
            'message': str(error),
            'status_code': 500
        }), 500

    @app.errorhandler(502)
    def bad_gateway_error(error):
        logger.error(f"Bad Gateway: {str(error)}")
        return jsonify({
            'error': 'Bad Gateway',
            'message': str(error),
            'status_code': 502
        }), 502

    @app.errorhandler(503)
    def service_unavailable_error(error):
        logger.error(f"Service Unavailable: {str(error)}")
        return jsonify({
            'error': 'Service Unavailable',
            'message': str(error),
            'status_code': 503
        }), 503

    @app.errorhandler(504)
    def gateway_timeout_error(error):
        logger.error(f"Gateway Timeout: {str(error)}")
        return jsonify({
            'error': 'Gateway Timeout',
            'message': str(error),
            'status_code': 504
        }), 504

    @app.errorhandler(LoopDetected)
    def infinite_loop_error(error):
        logger.error(f"Infinite Loop Detected: {str(error)}")
        return jsonify({
            'error': 'Loop Detected',
            'message': str(error),
            'status_code': 508
        }), 508

    @app.errorhandler(Exception)
    def handle_exception(error):
        """Handle all unhandled exceptions"""
        logger.error(f"Unhandled Exception: {str(error)}")
        if isinstance(error, HTTPException):
            return jsonify({
                'error': error.name,
                'message': error.description,
                'status_code': error.code
            }), error.code
        return jsonify({
            'error': 'Internal Server Error',
            'message': str(error),
            'status_code': 500
        }), 500

    # Custom error handler for deployment-related errors
    @app.errorhandler(402)
    def deployment_disabled_error(error):
        logger.error(f"Deployment Disabled: {str(error)}")
        return jsonify({
            'error': 'Deployment Disabled',
            'message': str(error),
            'status_code': 402
        }), 402

    @app.errorhandler(410)
    def deployment_deleted_error(error):
        logger.error(f"Deployment Deleted: {str(error)}")
        return jsonify({
            'error': 'Deployment Deleted',
            'message': str(error),
            'status_code': 410
        }), 410

    # Add middleware for request validation
    @app.before_request
    def validate_request():
        """Validate incoming requests"""
        try:
            # Check request method
            if request.method not in ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']:
                raise MethodNotAllowed(f"Method {request.method} not allowed")

            # Check request size
            if request.content_length and request.content_length > 10 * 1024 * 1024:  # 10MB limit
                raise RequestEntityTooLarge("Request payload too large")

            # Check URL length
            if len(request.url) > 2048:  # 2KB limit
                raise RequestURITooLong("URL too long")

        except Exception as e:
            logger.error(f"Request validation error: {str(e)}")
            raise

    return app 