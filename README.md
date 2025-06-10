# HaoSpeedTest - Free Cross-Network Speed Testing

A free, open-source speed testing tool that allows users to test network speeds between devices across different networks without requiring third-party apps.

## Features

- Cross-network speed testing
- No third-party apps required
- Real-time connection status
- Beautiful, modern UI
- Free hosting options

## Free Hosting Options

### Option 1: GitHub Pages + Render.com (Recommended)

1. Fork this repository to your GitHub account
2. Create a new repository on GitHub
3. Push the code to your repository
4. Go to [Render.com](https://render.com) and create a free account
5. Create a new Web Service and connect it to your GitHub repository
6. Set the following environment variables:
   - `PYTHON_VERSION`: 3.9.0
   - `PORT`: 8080
7. Deploy the service
8. Your app will be available at `https://your-app-name.onrender.com`

### Option 2: PythonAnywhere (Alternative)

1. Create a free account on [PythonAnywhere](https://www.pythonanywhere.com)
2. Create a new web app
3. Upload the code to your PythonAnywhere account
4. Set up a virtual environment and install requirements
5. Configure the web app to use your code
6. Your app will be available at `https://your-username.pythonanywhere.com`

## Local Development

1. Clone the repository:
```bash
git clone https://github.com/your-username/haospeedtest.git
cd haospeedtest
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the development server:
```bash
python app.py
```

5. Open http://localhost:5000 in your browser

## Usage

1. Open the website on both devices
2. On Device 1:
   - Click "Create New Room"
   - Copy the generated link
   - Share the link with Device 2

3. On Device 2:
   - Open the shared link
   - Wait for connection to establish
   - Start speed test when ready

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
