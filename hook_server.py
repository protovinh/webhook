from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json
    print(data)
    # Process the incoming email data here
    return jsonify({'status': 'success'}), 200

if __name__ == '__main__':
    app.run(port=5000)
