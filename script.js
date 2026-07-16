let completedLessons = JSON.parse(localStorage.getItem('completedLessons')) || [];
let totalXP = parseInt(localStorage.getItem('totalXP')) || 0;

document.addEventListener('DOMContentLoaded', function() {
    initNavigation();
    initTerminal();
    initToolFilters();
    updateStats();
    updateLessonStatuses();
});

function initNavigation() {
    const navLinks = document.querySelectorAll('.nav-link');
    const sections = document.querySelectorAll('.section');
    const hamburger = document.querySelector('.hamburger');
    const navLinksContainer = document.querySelector('.nav-links');

    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href').substring(1);
            
            navLinks.forEach(l => l.classList.remove('active'));
            sections.forEach(s => s.classList.remove('active'));
            
            this.classList.add('active');
            document.getElementById(targetId).classList.add('active');
            
            if (navLinksContainer.classList.contains('active')) {
                navLinksContainer.classList.remove('active');
            }
        });
    });

    hamburger.addEventListener('click', function() {
        navLinksContainer.classList.toggle('active');
    });
}

function initTerminal() {
    const input = document.getElementById('terminal-input');
    const output = document.getElementById('terminal-output');

    const commands = {
        help: () => `Available commands:
  help     - Show this help message
  clear    - Clear the terminal
  scan     - Simulate network scan
  whoami   - Show user info
  hash     - Generate random hash
  encode   - Base64 encode text
  decode   - Base64 decode text
  ping     - Simulate ping command
  nmap     - Simulate Nmap scan
  status   - Show your progress
  xp       - Show total XP`,
        
        clear: () => {
            output.innerHTML = '<div class="terminal-line prompt">></div>';
            return null;
        },
        
        scan: () => {
            const devices = ['192.168.1.1', '192.168.1.15', '192.168.1.23', '192.168.1.42'];
            let result = 'Starting network scan...\n';
            devices.forEach((ip, i) => {
                const ports = [22, 80, 443, 8080].slice(0, Math.floor(Math.random() * 4) + 1);
                result += `\nHost: ${ip}\n  Status: Up\n  Ports: ${ports.join(', ')}\n  OS: ${['Linux', 'Windows', 'macOS'][Math.floor(Math.random() * 3)]}`;
            });
            result += '\n\nScan complete. 4 hosts found.';
            return result;
        },
        
        whoami: () => `User: CyberStart-Learner
Role: Security Enthusiast
XP: ${totalXP}
Lessons Completed: ${completedLessons.length}/15`,
        
        hash: () => {
            const chars = '0123456789abcdef';
            let hash = '';
            for (let i = 0; i < 64; i++) {
                hash += chars[Math.floor(Math.random() * chars.length)];
            }
            return `Generated SHA-256 hash:\n${hash}`;
        },
        
        encode: (args) => {
            if (!args) return 'Usage: encode <text>';
            return `Encoded: ${btoa(args)}`;
        },
        
        decode: (args) => {
            if (!args) return 'Usage: decode <base64>';
            try {
                return `Decoded: ${atob(args)}`;
            } catch {
                return 'Error: Invalid Base64 string';
            }
        },
        
        ping: () => {
            let result = 'PING localhost (127.0.0.1) 56(84) bytes of data.\n';
            for (let i = 0; i < 4; i++) {
                const time = (Math.random() * 50 + 10).toFixed(3);
                result += `64 bytes from 127.0.0.1: icmp_seq=${i+1} ttl=64 time=${time} ms\n`;
            }
            result += '\n--- localhost ping statistics ---\n4 packets transmitted, 4 received, 0% packet loss';
            return result;
        },
        
        nmap: (args) => {
            const target = args || '192.168.1.1';
            return `Starting Nmap scan on ${target}...
Nmap scan report for ${target}
Host is up (0.0023s latency).

PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
443/tcp  open   https
8080/tcp closed http-proxy
3306/tcp open   mysql

Nmap done: 1 IP address (1 host up) scanned in 0.45 seconds`;
        },
        
        status: () => {
            return `=== Your Progress ===
Completed Lessons: ${completedLessons.length}/15
Total XP: ${totalXP}
Current Level: ${Math.floor(totalXP / 100) + 1}
XP to Next Level: ${100 - (totalXP % 100)}`;
        },
        
        xp: () => `Total XP: ${totalXP}\nKeep learning to earn more!`
    };

    input.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            const value = this.value.trim();
            if (!value) return;

            const [cmd, ...args] = value.split(' ');
            const command = cmd.toLowerCase();
            
            const outputLine = document.createElement('div');
            outputLine.className = 'terminal-line';
            outputLine.textContent = `> ${value}`;
            output.insertBefore(outputLine, output.lastElementChild);

            if (commands[command]) {
                const result = commands[command](args.join(' '));
                if (result !== null) {
                    const resultLine = document.createElement('div');
                    resultLine.className = 'terminal-line';
                    resultLine.style.color = 'var(--accent-primary)';
                    resultLine.textContent = result;
                    output.insertBefore(resultLine, output.lastElementChild);
                }
            } else {
                const errorLine = document.createElement('div');
                errorLine.className = 'terminal-line';
                errorLine.style.color = 'var(--danger)';
                errorLine.textContent = `Command not found: ${command}. Type 'help' for available commands.`;
                output.insertBefore(errorLine, output.lastElementChild);
            }

            output.scrollTop = output.scrollHeight;
            this.value = '';
        }
    });
}

function initToolFilters() {
    const filterBtns = document.querySelectorAll('.filter-btn');
    const toolCards = document.querySelectorAll('.tool-card');

    filterBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            filterBtns.forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            
            const category = this.dataset.category;
            
            toolCards.forEach(card => {
                if (category === 'all' || card.dataset.category === category) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        });
    });
}

function updateStats() {
    document.querySelectorAll('.stat-number').forEach((stat, index) => {
        const values = [completedLessons.length, completedLessons.length * 2, Math.floor(totalXP / 10)];
        animateNumber(stat, values[index]);
    });
}

function animateNumber(element, target) {
    let current = 0;
    const increment = target / 30;
    const timer = setInterval(() => {
        current += increment;
        if (current >= target) {
            element.textContent = target;
            clearInterval(timer);
        } else {
            element.textContent = Math.floor(current);
        }
    }, 30);
}

function updateLessonStatuses() {
    completedLessons.forEach(lessonId => {
        const lesson = document.querySelector(`[data-lesson="${lessonId}"]`);
        if (lesson) {
            lesson.querySelector('.lesson-status').classList.add('completed');
        }
    });

    document.querySelectorAll('.path-card').forEach(card => {
        const lessons = card.querySelectorAll('.lesson-status');
        const completed = card.querySelectorAll('.lesson-status.completed');
        const progress = Math.round((completed.length / lessons.length) * 100);
        card.querySelector('.path-progress').textContent = `${progress}%`;
    });
}

function startLearningPath(level) {
    const lessons = {
        beginner: [
            { id: 1, title: 'Introduction to Cybersecurity', content: 'Cybersecurity is the practice of protecting systems, networks, and programs from digital attacks. These attacks are usually aimed at accessing, changing, or destroying sensitive information; extorting money from users; or interrupting normal business processes.\n\nKey Concepts:\n• Confidentiality - Keeping data secret from unauthorized users\n• Integrity - Ensuring data hasn\'t been tampered with\n• Availability - Making sure systems are accessible when needed' },
            { id: 2, title: 'Networking Fundamentals', content: 'Understanding networking is crucial for cybersecurity. Key concepts include:\n\n• IP Addresses: Unique identifiers for devices on a network\n• TCP/IP: The foundational protocol suite of the internet\n• DNS: Translates domain names to IP addresses\n• HTTP/HTTPS: Web communication protocols\n• Ports: Logical endpoints for network connections\n\nCommon Ports to Know:\n• 22 - SSH\n• 80 - HTTP\n• 443 - HTTPS\n• 3389 - RDP' },
            { id: 3, title: 'Operating System Basics', content: 'As a cybersecurity professional, you need to understand multiple operating systems:\n\nWindows:\n• Registry, Services, Event Logs\n• Task Manager, PowerShell\n\nLinux:\n• File system structure (/etc, /var, /home)\n• Package managers (apt, yum)\n• File permissions (chmod, chown)\n\nmacOS:\n• Unix-based like Linux\n• Gatekeeper, XProtect' },
            { id: 4, title: 'Security Principles', content: 'Core security principles every professional should know:\n\nDefense in Depth: Multiple layers of security\nLeast Privilege: Minimum necessary access\nZero Trust: Never trust, always verify\nDefense: Security should be proactive, not reactive\n\nSecurity Controls:\n• Technical: Firewalls, encryption, MFA\n• Administrative: Policies, training, procedures\n• Physical: Locks, badges, cameras' },
            { id: 5, title: 'Common Threats & Attacks', content: 'Common cyber threats you should understand:\n\nMalware:\n• Viruses, Worms, Trojans\n• Ransomware, Spyware\n\nSocial Engineering:\n• Phishing, Vishing, Smishing\n• Pretexting, Baiting\n\nNetwork Attacks:\n• Man-in-the-Middle\n• DDoS, DNS Poisoning\n• SQL Injection, XSS' }
        ],
        intermediate: [
            { id: 6, title: 'Linux Command Line', content: 'Essential Linux commands for cybersecurity:\n\nNavigation:\n• ls, cd, pwd, find\n\nFile Operations:\n• cp, mv, rm, mkdir, cat\n\nPermissions:\n• chmod, chown, sudo\n\nNetworking:\n• ifconfig, netstat, ss, curl\n\nProcess Management:\n• ps, top, kill\n\nText Processing:\n• grep, awk, sed, sort' },
            { id: 7, title: 'Web Application Security', content: 'Understanding web vulnerabilities (OWASP Top 10):\n\n1. Injection (SQL, NoSQL, LDAP)\n2. Broken Authentication\n3. Sensitive Data Exposure\n4. XML External Entities (XXE)\n5. Broken Access Control\n6. Security Misconfiguration\n7. Cross-Site Scripting (XSS)\n8. Insecure Deserialization\n9. Using Components with Known Vulnerabilities\n10. Insufficient Logging & Monitoring' },
            { id: 8, title: 'Network Security', content: 'Network security fundamentals:\n\nFirewalls:\n• Stateful vs Stateless\n• Next-Generation Firewalls\n\nIDS/IPS:\n• Signature-based detection\n• Anomaly-based detection\n\nVPN:\n• Site-to-site vs Remote access\n• IPSec, WireGuard, OpenVPN\n\nNetwork Segmentation:\n• VLANs, DMZ, Subnetting' },
            { id: 9, title: 'Cryptography Basics', content: 'Essential cryptography concepts:\n\nSymmetric Encryption:\n• AES, DES, 3DES\n• Same key for encrypt/decrypt\n\nAsymmetric Encryption:\n• RSA, ECC\n• Public/private key pairs\n\nHashing:\n• MD5, SHA-1, SHA-256\n• One-way functions\n\nOther:\n• Digital signatures\n• Certificates (X.509)\n• PKI infrastructure' },
            { id: 10, title: 'Introduction to Pentesting', content: 'Penetration testing methodology:\n\n1. Reconnaissance (Passive & Active)\n2. Scanning & Enumeration\n3. Vulnerability Assessment\n4. Exploitation\n5. Post-Exploitation\n6. Reporting\n\nTools:\n• Nmap, Masscan\n• Metasploit\n• Burp Suite\n• John the Ripper' }
        ],
        advanced: [
            { id: 11, title: 'Vulnerability Assessment', content: 'Advanced vulnerability assessment:\n\nScanning Tools:\n• Nessus, Qualys, OpenVAS\n• Nikto, OWASP ZAP\n\nVulnerability Management:\n• CVE database\n• CVSS scoring\n• Risk prioritization\n\nReporting:\n• Executive summaries\n• Technical findings\n• Remediation guidance' },
            { id: 12, title: 'Penetration Testing', content: 'Advanced penetration testing:\n\nMethodologies:\n• PTES (Penetration Testing Execution Standard)\n• OWASP Testing Guide\n• NIST SP 800-115\n\nTechniques:\n• Privilege escalation\n• Lateral movement\n• Pivoting\n• Persistence\n\nTools:\n• Cobalt Strike\n• Empire\n• BloodHound' },
            { id: 13, title: 'Incident Response', content: 'Incident response lifecycle:\n\n1. Preparation\n2. Detection & Analysis\n3. Containment\n4. Eradication\n5. Recovery\n6. Post-Incident Activity\n\nKey Concepts:\n• Chain of custody\n• Forensic imaging\n• Log analysis\n• Threat intelligence' },
            { id: 14, title: 'Malware Analysis', content: 'Malware analysis techniques:\n\nStatic Analysis:\n• File hashing\n• String extraction\n• PE header analysis\n\nDynamic Analysis:\n• Sandbox execution\n• Network traffic capture\n• Registry changes\n\nTools:\n• IDA Pro, Ghidra\n• VirusTotal\n• Cuckoo Sandbox' },
            { id: 15, title: 'Advanced Exploitation', content: 'Advanced exploitation techniques:\n\nExploit Development:\n• Buffer overflows\n• ROP chains\n• Shellcode\n\nWeb Exploitation:\n• Advanced SQLi\n• XXE, SSRF\n• Deserialization attacks\n\nBinary Exploitation:\n• Heap spraying\n• Format strings\n• Use-after-free' }
        ]
    };

    const lessonsList = lessons[level];
    if (lessonsList && lessonsList.length > 0) {
        showLesson(lessonsList[0], lessonsList, 0);
    }
}

function showLesson(lesson, lessonsList, index) {
    const modal = document.getElementById('lesson-modal');
    const modalBody = document.getElementById('modal-body');
    
    modalBody.innerHTML = `
        <h2>${lesson.title}</h2>
        <div class="lesson-content">
            <p>${lesson.content.replace(/\n/g, '<br>')}</p>
        </div>
        <div class="lesson-actions">
            ${index > 0 ? '<button class="btn-secondary" onclick="prevLesson()">Previous</button>' : '<div></div>'}
            <button class="btn-primary" onclick="completeLesson(${lesson.id}, ${JSON.stringify(lessonsList).replace(/"/g, '&quot;')}, ${index})">Complete & Continue</button>
        </div>
    `;
    
    modal.classList.add('active');
    window.currentLessonsList = lessonsList;
    window.currentLessonIndex = index;
}

function completeLesson(lessonId, lessonsList, index) {
    if (!completedLessons.includes(lessonId)) {
        completedLessons.push(lessonId);
        totalXP += 50;
        localStorage.setItem('completedLessons', JSON.stringify(completedLessons));
        localStorage.setItem('totalXP', totalXP.toString());
    }
    
    updateLessonStatuses();
    updateStats();
    
    if (lessonsList && index < lessonsList.length - 1) {
        showLesson(lessonsList[index + 1], lessonsList, index + 1);
    } else {
        closeModal();
    }
}

function closeModal() {
    document.getElementById('lesson-modal').classList.remove('active');
}

function startChallenge(type) {
    const challenges = {
        base64: {
            title: 'Base64 Decode Challenge',
            question: 'Decode this Base64 string: Q3liZXJTdGFydA==',
            answer: 'CyberStart'
        },
        hash: {
            title: 'Hash Identification Challenge',
            question: 'What hash type is this?\n5d41402abc4b2a76b9719d911017c592',
            answer: 'MD5'
        },
        xor: {
            title: 'XOR Cipher Challenge',
            question: 'XOR these two hex values:\n41 XOR 35 = ?\n(Answer in hex)',
            answer: '74'
        },
        stego: {
            title: 'Steganography Challenge',
            question: 'Hint: Look for hidden data in image metadata.\nWhat tool would you use first?',
            answer: 'exiftool'
        },
        forensics: {
            title: 'Memory Forensics Challenge',
            question: 'Which Volatility plugin processes a memory dump to list processes?',
            answer: 'pslist'
        }
    };

    const challenge = challenges[type];
    const userAnswer = prompt(`${challenge.title}\n\n${challenge.question}`);
    
    if (userAnswer) {
        if (userAnswer.toLowerCase() === challenge.answer.toLowerCase()) {
            alert('Correct! +XP earned');
            totalXP += 25;
            localStorage.setItem('totalXP', totalXP.toString());
            updateStats();
        } else {
            alert(`Incorrect. The answer was: ${challenge.answer}`);
        }
    }
}

function base64Encode() {
    const input = document.getElementById('base64-input').value;
    const output = document.getElementById('base64-output');
    
    try {
        output.textContent = btoa(input);
    } catch {
        output.textContent = 'Error: Invalid input';
    }
}

function base64Decode() {
    const input = document.getElementById('base64-input').value;
    const output = document.getElementById('base64-output');
    
    try {
        output.textContent = atob(input);
    } catch {
        output.textContent = 'Error: Invalid Base64 string';
    }
}

async function generateHash(algorithm) {
    const input = document.getElementById('hash-input').value;
    const output = document.getElementById('hash-output');
    
    if (!input) {
        output.textContent = 'Please enter text to hash';
        return;
    }

    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    
    let hashAlgorithm;
    switch(algorithm) {
        case 'MD5':
            output.textContent = await md5(input);
            return;
        case 'SHA-1':
            hashAlgorithm = 'SHA-1';
            break;
        case 'SHA-256':
            hashAlgorithm = 'SHA-256';
            break;
    }
    
    const hashBuffer = await crypto.subtle.digest(hashAlgorithm, data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    output.textContent = hashHex;
}

async function md5(string) {
    function md5cycle(x, k) {
        var a = x[0], b = x[1], c = x[2], d = x[3];
        a = ff(a, b, c, d, k[0], 7, -680876936);d = ff(d, a, b, c, k[1], 12, -389564586);c = ff(c, d, a, b, k[2], 17, 606105819);b = ff(b, c, d, a, k[3], 22, -1044525330);a = ff(a, b, c, d, k[4], 7, -176418897);d = ff(d, a, b, c, k[5], 12, 1200080426);c = ff(c, d, a, b, k[6], 17, -1473231341);b = ff(b, c, d, a, k[7], 22, -45705983);a = ff(a, b, c, d, k[8], 7, 1770035416);d = ff(d, a, b, c, k[9], 12, -1958414417);c = ff(c, d, a, b, k[10], 17, -42063);b = ff(b, c, d, a, k[11], 22, -1990404162);a = ff(a, b, c, d, k[12], 7, 1804603682);d = ff(d, a, b, c, k[13], 12, -40341101);c = ff(c, d, a, b, k[14], 17, -1502002290);b = ff(b, c, d, a, k[15], 22, 1236535329);a = gg(a, b, c, d, k[1], 5, -165796510);d = gg(d, a, b, c, k[6], 9, -1069501632);c = gg(c, d, a, b, k[11], 14, 643717713);b = gg(b, c, d, a, k[0], 20, -373897302);a = gg(a, b, c, d, k[5], 5, -701558691);d = gg(d, a, b, c, k[10], 9, 38016083);c = gg(c, d, a, b, k[15], 14, -660478335);b = gg(b, c, d, a, k[4], 20, -405537848);a = gg(a, b, c, d, k[9], 5, 568446438);d = gg(d, a, b, c, k[14], 9, -1019803690);c = gg(c, d, a, b, k[3], 14, -187363961);b = gg(b, c, d, a, k[8], 20, 1163531501);a = gg(a, b, c, d, k[13], 5, -1444681467);d = gg(d, a, b, c, k[2], 9, -51403784);c = gg(c, d, a, b, k[7], 14, 1735328473);b = gg(b, c, d, a, k[12], 20, -1926607734);a = hh(a, b, c, d, k[5], 4, -378558);d = hh(d, a, b, c, k[8], 11, -2022574463);c = hh(c, d, a, b, k[11], 16, 1839030562);b = hh(b, c, d, a, k[14], 23, -35309556);a = hh(a, b, c, d, k[1], 4, -1530992060);d = hh(d, a, b, c, k[4], 11, 1272893353);c = hh(c, d, a, b, k[7], 16, -155497632);b = hh(b, c, d, a, k[10], 23, -1094730640);a = hh(a, b, c, d, k[13], 4, 681279174);d = hh(d, a, b, c, k[0], 11, -358537222);c = hh(c, d, a, b, k[3], 16, -722521979);b = hh(b, c, d, a, k[6], 23, 76029189);a = hh(a, b, c, d, k[9], 4, -640364487);d = hh(d, a, b, c, k[12], 11, -421815835);c = hh(c, d, a, b, k[15], 16, 530742520);b = hh(b, c, d, a, k[2], 23, -995338651);a = ii(a, b, c, d, k[0], 6, -198630844);d = ii(d, a, b, c, k[7], 10, 1126891415);c = ii(c, d, a, b, k[14], 15, -1416354905);b = ii(b, c, d, a, k[5], 21, -57434055);a = ii(a, b, c, d, k[12], 6, 1700485571);d = ii(d, a, b, c, k[3], 10, -1894986606);c = ii(c, d, a, b, k[10], 15, -1051523);b = ii(b, c, d, a, k[1], 21, -2054922799);a = ii(a, b, c, d, k[8], 6, 1873313359);d = ii(d, a, b, c, k[15], 10, -30611744);c = ii(c, d, a, b, k[6], 15, -1560198380);b = ii(b, c, d, a, k[13], 21, 1309151649);a = ii(a, b, c, d, k[4], 6, -145523070);d = ii(d, a, b, c, k[11], 10, -1120210379);c = ii(c, d, a, b, k[2], 15, 718787259);b = ii(b, c, d, a, k[9], 21, -343485551);
        x[0] = add32(a, x[0]);x[1] = add32(b, x[1]);x[2] = add32(c, x[2]);x[3] = add32(d, x[3]);
    }
    function cmn(q, a, b, x, s, t) {
        a = add32(add32(a, q), add32(x, t));
        return add32((a << s) | (a >>> (32 - s)), b);
    }
    function ff(a, b, c, d, x, s, t) { return cmn((b & c) | ((~b) & d), a, b, x, s, t); }
    function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & (~d)), a, b, x, s, t); }
    function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
    function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | (~d)), a, b, x, s, t); }
    function md51(s) {
        var n = s.length, state = [1732584193, -271733879, -1732584194, 271733878], i;
        for (i = 64; i <= s.length; i += 64) {
            md5cycle(state, md5blk(s.substring(i - 64, i)));
        }
        s = s.substring(i - 64);
        var tail = [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0];
        for (i = 0; i < s.length; i++)
            tail[i >> 2] |= s.charCodeAt(i) << ((i % 4) << 3);
        tail[i >> 2] |= 0x80 << ((i % 4) << 3);
        if (i > 55) {
            md5cycle(state, tail);
            for (i = 0; i < 16; i++) tail[i] = 0;
        }
        tail[14] = n * 8;
        md5cycle(state, tail);
        return state;
    }
    function md5blk(s) {
        var md5blks = [], i;
        for (i = 0; i < 64; i += 4) {
            md5blks[i >> 2] = s.charCodeAt(i) + (s.charCodeAt(i + 1) << 8) + (s.charCodeAt(i + 2) << 16) + (s.charCodeAt(i + 3) << 24);
        }
        return md5blks;
    }
    var hex_chr = '0123456789abcdef'.split('');
    function rhex(n) {
        var s = '', j = 0;
        for (; j < 4; j++)
            s += hex_chr[(n >> (j * 8 + 4)) & 0x0F] + hex_chr[(n >> (j * 8)) & 0x0F];
        return s;
    }
    function hex(x) {
        for (var i = 0; i < x.length; i++)
            x[i] = rhex(x[i]);
        return x.join('');
    }
    function add32(a, b) {
        return (a + b) & 0xFFFFFFFF;
    }
    return hex(md51(string));
}

function urlEncode() {
    const input = document.getElementById('url-input').value;
    const output = document.getElementById('url-output');
    output.textContent = encodeURIComponent(input);
}

function urlDecode() {
    const input = document.getElementById('url-input').value;
    const output = document.getElementById('url-output');
    try {
        output.textContent = decodeURIComponent(input);
    } catch {
        output.textContent = 'Error: Invalid URL encoded string';
    }
}

function textToHex() {
    const input = document.getElementById('hex-input').value;
    const output = document.getElementById('hex-output');
    let hex = '';
    for (let i = 0; i < input.length; i++) {
        hex += input.charCodeAt(i).toString(16).padStart(2, '0') + ' ';
    }
    output.textContent = hex.trim();
}

function hexToText() {
    const input = document.getElementById('hex-input').value.replace(/\s/g, '');
    const output = document.getElementById('hex-output');
    let text = '';
    for (let i = 0; i < input.length; i += 2) {
        text += String.fromCharCode(parseInt(input.substr(i, 2), 16));
    }
    output.textContent = text;
}

document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeModal();
    }
});
