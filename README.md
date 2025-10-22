# 🛡️ Advanced DLP (Data Loss Prevention) System

A comprehensive, enterprise-grade Data Loss Prevention system built with Flask, featuring advanced policy engines, user authentication, real-time monitoring, and comprehensive security controls.

## ✨ Key Features

### 🔐 **Security & Authentication**
- **User Authentication**: Secure login/logout with Flask-Login
- **Role-based Access Control**: Admin and regular user roles
- **Password Security**: Bcrypt hashing for secure password storage
- **Session Management**: Secure session handling with CSRF protection

### 🛡️ **Advanced DLP Engine**
- **10+ Built-in Policies**: Credit cards, SSNs, API keys, JWT tokens, passwords, etc.
- **Customizable Rules**: Database-driven policy management
- **Severity Levels**: Critical, High, Medium, Low classification
- **Real-time Scanning**: Instant content analysis and blocking
- **External Recipient Protection**: Special policies for external communications

### 📊 **Comprehensive Monitoring**
- **Real-time Dashboard**: Live statistics and activity monitoring
- **Security Incidents**: Automated incident creation and tracking
- **System Logging**: Comprehensive audit trail
- **Policy Violation Analytics**: Detailed violation reporting by category

### 🗄️ **Database Integration**
- **SQLite Database**: Persistent storage for all data
- **User Management**: Complete user lifecycle management
- **Email Logging**: Full audit trail of all email attempts
- **Policy Management**: Dynamic policy configuration

### 🎨 **Modern UI/UX**
- **Responsive Design**: Bootstrap 5 with modern styling
- **Interactive Dashboard**: Real-time statistics and charts
- **User-friendly Interface**: Intuitive navigation and forms
- **Mobile Support**: Fully responsive across all devices

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip (Python package installer)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd dlp2
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment** (Optional)
   ```bash
   cp env_example.txt .env
   # Edit .env with your configuration
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Access the system**
   - Open your browser to `http://localhost:5000`
   - Login with demo credentials (see below)

## 👥 Demo Accounts

### Admin Account
- **Email**: `admin@dlp-system.com`
- **Password**: `admin123`
- **Access**: Full system administration

### Regular Users
- **Alice**: `alice@example.com` / `demo123`
- **Bob**: `bob@example.com` / `demo123`
- **Charlie (External)**: `charlie@external.com` / `demo123`

## 🏗️ System Architecture

### Core Components

1. **Authentication System** (`auth.py`)
   - User registration and login
   - Password security with bcrypt
   - Session management

2. **DLP Engine** (`dlp/dlp_engine.py`)
   - Policy-based content scanning
   - Regex pattern matching
   - Severity-based blocking

3. **Database Models** (`models.py`)
   - User management
   - Email logging
   - Policy configuration
   - Security incidents

4. **Web Interface** (`templates/`)
   - Dashboard with real-time stats
   - Email composition interface
   - Admin management panels

### Database Schema

- **Users**: User accounts with roles and permissions
- **EmailLog**: Complete audit trail of email attempts
- **DLPPolicy**: Configurable security policies
- **SecurityIncident**: Automated incident tracking
- **SystemLog**: Comprehensive system logging

## 🛡️ DLP Policies

### Built-in Detection Rules

1. **Financial Data**
   - Credit card numbers (13-19 digits)
   - IBAN numbers
   - Bank account patterns

2. **Personal Information**
   - Social Security Numbers (SSN)
   - Phone numbers
   - Email addresses

3. **Credentials & Keys**
   - Passwords and API keys
   - AWS access keys
   - JWT tokens
   - Database connection strings

4. **Sensitive Keywords**
   - Confidential, secret, classified
   - Internal-only content
   - Proprietary information

### Policy Configuration

Policies can be:
- **Enabled/Disabled**: Toggle individual policies
- **Customized**: Modify regex patterns and severity
- **Categorized**: Organize by data type and risk level
- **Monitored**: Track violation statistics

## 📊 Admin Features

### Dashboard Analytics
- Total emails sent/blocked
- User activity statistics
- Policy violation trends
- Security incident overview

### User Management
- Add/remove users
- Activate/deactivate accounts
- Role assignment
- Password management

### Policy Management
- View all DLP policies
- Enable/disable rules
- Modify detection patterns
- Monitor policy effectiveness

### System Monitoring
- Real-time system logs
- Security incident tracking
- Performance metrics
- Audit trail review

## 🔧 Configuration

### Environment Variables

Create a `.env` file with:

```env
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///dlp_system.db
ADMIN_EMAIL=admin@dlp-system.com
ADMIN_PASSWORD=admin123
LOG_LEVEL=INFO
```

### Security Settings

- **CSRF Protection**: Enabled by default
- **Session Security**: Configurable cookie settings
- **Password Requirements**: Minimum 8 characters
- **Access Control**: Role-based permissions

## 🚨 Security Features

### Data Protection
- **Content Scanning**: Real-time analysis of all communications
- **Pattern Matching**: Advanced regex-based detection
- **Blocking**: Automatic prevention of data leaks
- **Logging**: Complete audit trail

### Access Control
- **Authentication**: Secure user login system
- **Authorization**: Role-based access control
- **Session Management**: Secure session handling
- **Admin Controls**: Restricted administrative functions

### Monitoring & Alerting
- **Real-time Alerts**: Immediate notification of violations
- **Incident Tracking**: Automated security incident creation
- **Audit Logging**: Comprehensive system activity logs
- **Statistics**: Detailed analytics and reporting

## 🔄 API Endpoints

### REST API
- `GET /api/stats` - Dashboard statistics
- `POST /send` - Send email with DLP scanning
- `GET /incidents` - View security incidents

### Authentication
- `POST /auth/login` - User authentication
- `POST /auth/register` - User registration
- `GET /auth/logout` - User logout

## 🛠️ Development

### Project Structure
```
dlp2/
├── app.py                 # Main application
├── config.py             # Configuration settings
├── models.py             # Database models
├── auth.py               # Authentication system
├── dlp/
│   ├── dlp_engine.py     # DLP policy engine
│   └── policies.py       # Policy definitions
├── templates/            # HTML templates
├── static/              # CSS and assets
├── logs/                # Log files
└── requirements.txt     # Dependencies
```

### Adding New Policies

1. **Define Pattern**: Create regex pattern for detection
2. **Set Severity**: Choose appropriate risk level
3. **Add to Engine**: Update DLP engine with new rule
4. **Test**: Verify detection accuracy

### Customizing UI

- **Templates**: Modify HTML templates in `templates/`
- **Styling**: Update CSS in `static/style.css`
- **Components**: Add new Bootstrap components

## 📈 Performance

### Optimization Features
- **Database Indexing**: Optimized queries for large datasets
- **Pagination**: Efficient handling of large result sets
- **Caching**: Session-based caching for improved performance
- **Async Processing**: Non-blocking policy evaluation

### Scalability
- **Modular Design**: Easy to extend and modify
- **Database Agnostic**: Can be adapted to PostgreSQL/MySQL
- **API Ready**: RESTful endpoints for integration
- **Microservice Ready**: Can be containerized with Docker

## 🔍 Troubleshooting

### Common Issues

1. **Database Errors**
   - Ensure SQLite database is writable
   - Check file permissions in project directory

2. **Authentication Issues**
   - Verify user credentials
   - Check session configuration

3. **Policy Detection**
   - Review regex patterns
   - Test with sample content

### Logs
- **System Logs**: `logs/dlp_system.log`
- **Application Logs**: Console output
- **Error Tracking**: Flask debug mode

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the documentation

---

**Built with ❤️ for enterprise security and data protection**
