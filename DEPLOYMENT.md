# HaoSpeedTest Deployment Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Local Development Setup](#local-development-setup)
3. [Deployment to Render](#deployment-to-render)
4. [Troubleshooting](#troubleshooting)
5. [Maintenance](#maintenance)

## Prerequisites

### Required Software
- Python 3.9 or higher
- Git
- pip (Python package manager)
- A GitHub account
- A Render account

### Required Accounts
1. GitHub Account
   - Create at: https://github.com/signup
   - Enable two-factor authentication for security

2. Render Account
   - Create at: https://render.com/signup
   - Connect your GitHub account

## Local Development Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/haospeedtest.git
cd haospeedtest
```

2. Create and activate a virtual environment:
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application locally:
```bash
python run.py
```

5. Test the application:
- Open http://localhost:5000 in your browser
- Run the connection test: `python connection_test.py`

## Deployment to Render

1. Push your code to GitHub:
```bash
git add .
git commit -m "Initial deployment"
git push origin main
```

2. Deploy on Render:
   - Log in to Render
   - Click "New +" and select "Web Service"
   - Connect your GitHub repository
   - Configure the service:
     - Name: haospeedtest
     - Environment: Python
     - Build Command: `pip install -r requirements.txt`
     - Start Command: `python run.py`
   - Click "Create Web Service"

3. Configure Environment Variables:
   - Go to your service's "Environment" tab
   - Add the following variables:
     ```
     PYTHON_VERSION=3.9.0
     PORT=5000
     ```

4. Monitor Deployment:
   - Check the "Logs" tab for deployment progress
   - Verify the service is running at your Render URL

## Troubleshooting

### Common Issues

1. Connection Refused
   - Check if the server is running
   - Verify firewall settings
   - Run the connection test script
   - Check port availability

2. Deployment Failures
   - Check Render logs for errors
   - Verify all dependencies are in requirements.txt
   - Ensure Python version compatibility

3. Performance Issues
   - Monitor resource usage in Render dashboard
   - Check application logs
   - Run network diagnostics

### Diagnostic Tools

1. Connection Test:
```bash
python connection_test.py
```

2. Network Diagnostics:
```bash
python network_diagnostics.py
```

3. Server Logs:
```bash
tail -f server.log
```

## Maintenance

### Regular Tasks

1. Update Dependencies:
```bash
pip freeze > requirements.txt
git add requirements.txt
git commit -m "Update dependencies"
git push
```

2. Monitor Performance:
- Check Render dashboard regularly
- Review application logs
- Monitor resource usage

3. Backup Data:
- Export any important data
- Keep local backups
- Use version control for code

### Security Updates

1. Regular Updates:
- Update Python packages
- Check for security vulnerabilities
- Update SSL certificates

2. Access Control:
- Review user permissions
- Monitor access logs
- Update security policies

## Support

For additional support:
1. Check the documentation
2. Review the troubleshooting guide
3. Contact support at support@haospeedtest.com

## License

This project is licensed under the MIT License - see the LICENSE file for details. 