#!/usr/bin/env python3
"""
DLP System Startup Script
Run this script to start the DLP system with proper initialization
"""

import os
import sys
from app import app, init_db

def main():
    """Main startup function"""
    print("🛡️  Starting DLP System...")
    print("=" * 50)
    
    # Ensure we're in the correct directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    # Initialize database
    print("📊 Initializing database...")
    try:
        init_db()
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        sys.exit(1)
    
    # Start the application
    print("🚀 Starting Flask application...")
    print("🌐 Access the system at: http://localhost:5000")
    print("👤 Admin login: admin@dlp-system.com / admin123")
    print("👥 Demo users: alice@example.com / demo123")
    print("=" * 50)
    print("Press Ctrl+C to stop the server")
    print("=" * 50)
    
    try:
        app.run(debug=True, host="127.0.0.1", port=5000)
    except KeyboardInterrupt:
        print("\n👋 DLP System stopped. Goodbye!")
    except Exception as e:
        print(f"❌ Application error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
