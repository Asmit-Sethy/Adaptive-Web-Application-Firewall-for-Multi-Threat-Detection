from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/', methods=['POST', 'GET'])
def handle_request():
    if request.method == 'POST':
        # Expecting JSON data
        data = request.get_json()  # This will parse the incoming JSON
        if data is None:
            return jsonify({'status': 'error', 'message': 'Invalid JSON'}), 400
        return jsonify({'status': 'success', 'message': 'Request received by backend', 'data': data}), 200

    return jsonify({'status': 'success', 'message': 'Request received by backend'}), 200

if __name__ == '__main__':
    app.run(port=8080)  # Run on port 8080 (non-SSL)
