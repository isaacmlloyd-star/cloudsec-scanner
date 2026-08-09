import VConsole from 'vconsole';
if (typeof window !== 'undefined') {
  new VConsole();
} 

import React, { useState, useEffect } from 'react';
import { initializeApp } from 'firebase/app';
import { getAuth, signInWithCustomToken, signInAnonymously, onAuthStateChanged } from 'firebase/auth';
import { getFirestore, collection, addDoc, onSnapshot } from 'firebase/firestore';
import { ShieldAlert, ShieldCheck, AlertTriangle, Play, RefreshCw, Database, Code, Clock } from 'lucide-react';

// --- 1. FIREBASE SYSTEM INITIALIZATION ---
const firebaseConfig = {
  apiKey: "AIzaSyB4bjUAjiIgTMJTZ8KG2HIe5_bPBbw0yhw",
  authDomain: "cloudsec-backend.firebaseapp.com",
  projectId: "cloudsec-backend",
  storageBucket: "cloudsec-backend.firebasestorage.app",
  messagingSenderId: "531281739638",
  appId: "1:531281739638:web:5ed84fdf4ec573fe654457"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

export default function App() {
  const [user, setUser] = useState(null);
  const [activeTab, setActiveTab] = useState('scanner'); // 'scanner' or 'dashboard'
  const [code, setCode] = useState('');
  const [analysis, setAnalysis] = useState('');
const [isAnalyzing, setIsAnalyzing] = useState(false);
const getVulnerabilityAnalysis = async (threatType, vulnerableSnippet) => {
  setIsAnalyzing(true);
  setAnalysis('');

  const apiKey = import.meta.env.VITE_GEMINI_API_KEY;
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`;

  const prompt = `
You are a code security auditor. Analyze the following issue found in static code analysis:

Threat Type: ${threatType}
Vulnerable Code:
${vulnerableSnippet}

Provide a concise breakdown:
1. Root Cause Analysis
2. Security Impact
3. Secure Code Remediation (show corrected code)
`;

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
      }),
    });

    const data = await response.json();
    const output = data.candidates?.[0]?.content?.parts?.[0]?.text || 'No analysis available.';
    setAnalysis(output);
  } catch (error) {
    console.error('Error fetching analysis:', error);
    setAnalysis('Failed to fetch vulnerability analysis. Check API key and network connection.');
  } finally {
    setIsAnalyzing(false);
  }
};

  const [isScanning, setIsScanning] = useState(false);
  const [scanHistory, setScanHistory] = useState([]);
  const [currentResults, setCurrentResults] = useState(null);

  // --- 2. AUTHENTICATION (The Security Gate) ---
  useEffect(() => {
    const initAuth = async () => {
      try {
        if (typeof __initial_auth_token !== 'undefined' && __initial_auth_token) {
          await signInWithCustomToken(auth, __initial_auth_token);
        } else {
          await signInAnonymously(auth);
        }
      } catch (err) {
        console.error("Auth failed:", err);
      }
    };
    initAuth();

    const unsubscribe = onAuthStateChanged(auth, (currentUser) => {
      setUser(currentUser);
    });
    return () => unsubscribe();
  }, []);

  // --- 3. DATABASE LISTENER (The Triage Dashboard) ---
  useEffect(() => {
    if (!user) return;

    // Secure, private path for this specific user
    const scansRef = collection(db, 'artifacts', firebaseConfig.appId, 'users', user.uid, 'scans');
    
    const unsubscribe = onSnapshot(scansRef, (snapshot) => {
      const scans = snapshot.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      }));
      
      // Sort in JS (No complex queries allowed in MVP)
      scans.sort((a, b) => b.timestamp - a.timestamp);
      setScanHistory(scans);
    }, (error) => {
      console.error("Database sync failed:", error);
    });

    return () => unsubscribe();
  }, [user]);

  // --- 4. THE SCANNER ENGINE ---
  const RULES = [
    { 
      name: 'Hardcoded API/Secret Key', 
      regex: /(password|secret|api_key|token)\s*=\s*['"][^'"]+['"]/i, 
      severity: 'High'
    },
    { 
      name: 'Command Injection Risk', 
      regex: /(os\.system|subprocess\.Popen|eval|exec)\(/, 
      severity: 'Critical'
    },
    { 
      name: 'SQL Injection Risk', 
      regex: /(execute\(\s*f['"].*?\{.*?\}|SELECT.*FROM.*WHERE.*=.*\+)/i, 
      severity: 'Critical'
    }
  ];

  const handleScan = async () => {
    if (!code.trim() || !user) return;
    
    setIsScanning(true);
    setCurrentResults(null);

    // Simulate engine processing time
    setTimeout(async () => {
      const lines = code.split('\n');
      const foundVulnerabilities = [];

      lines.forEach((line, index) => {
        const lineNum = index + 1;
        RULES.forEach(rule => {
          if (rule.regex.test(line)) {
            foundVulnerabilities.push({
              lineNum,
              codeSnippet: line.trim(),
              name: rule.name,
              severity: rule.severity
            });
          }
        });
      });

      setCurrentResults(foundVulnerabilities);
      setIsScanning(false);

      // --- 5. SAVE TO CLOUD ---
      try {
        const scansRef = collection(db, 'artifacts', appId, 'users', user.uid, 'scans');
        await addDoc(scansRef, {
          timestamp: Date.now(),
          threatCount: foundVulnerabilities.length,
          vulnerabilities: foundVulnerabilities,
          codePreview: code.substring(0, 100) + '...' // Save a snippet of what was scanned
        });
      } catch (err) {
        console.error("Failed to save scan to cloud:", err);
      }

    }, 800);
  };

  const loadExample = () => {
    setCode(`def connect_to_db(user_input):
    api_key = "sk_live_123456789"
    eval(user_input)
    query = f"SELECT * FROM users WHERE id = {user_input}"
    db.execute(query)`);
  };

  if (!user) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center p-4">
        <div className="text-emerald-400 flex flex-col items-center gap-3">
          <RefreshCw className="animate-spin" size={32} />
          <p className="font-mono text-sm">Initializing Secure Environment...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 font-sans">
      {/* Top Navigation */}
      <nav className="bg-slate-950 border-b border-slate-800 px-4 py-3 flex justify-between items-center sticky top-0 z-10">
        <div className="flex items-center gap-2">
          <ShieldAlert className="text-emerald-500" size={24} />
          <span className="font-bold text-lg tracking-tight">CloudSec MVP</span>
        </div>
        <div className="flex bg-slate-800 rounded-lg p-1">
          <button 
            onClick={() => setActiveTab('scanner')}
            className={`px-4 py-1.5 rounded-md text-sm font-semibold transition-colors flex items-center gap-2 ${activeTab === 'scanner' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'}`}
          >
            <Code size={16} /> <span className="hidden sm:inline">Scanner</span>
          </button>
          <button 
            onClick={() => setActiveTab('dashboard')}
            className={`px-4 py-1.5 rounded-md text-sm font-semibold transition-colors flex items-center gap-2 ${activeTab === 'dashboard' ? 'bg-emerald-600 text-white' : 'text-slate-400 hover:text-white'}`}
          >
            <Database size={16} /> <span className="hidden sm:inline">History</span>
            {scanHistory.length > 0 && (
              <span className="bg-slate-900 text-emerald-400 text-xs px-1.5 py-0.5 rounded-full ml-1">
                {scanHistory.length}
              </span>
            )}
          </button>
        </div>
      </nav>

      <main className="max-w-3xl mx-auto p-4 md:p-6">
        
        {/* SCANNER VIEW */}
        {activeTab === 'scanner' && (
          <div className="space-y-6 animate-in fade-in duration-300">
            <div className="space-y-2">
              <div className="flex justify-between items-end">
                <label className="text-sm font-semibold text-slate-300">Target Source Code</label>
                <button 
                  onClick={loadExample}
                  className="text-xs text-emerald-400 hover:text-emerald-300 flex items-center gap-1"
                >
                  <RefreshCw size={14} /> Load Bad Code
                </button>
              </div>
              <textarea
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="Paste code here to scan..."
                className="w-full h-64 bg-slate-950 border border-slate-700 rounded-lg p-4 font-mono text-sm text-emerald-400 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
                spellCheck="false"
              />
            </div>

            <button
              onClick={handleScan}
              disabled={isScanning || !code.trim()}
              className="w-full bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-bold py-4 px-4 rounded-lg flex items-center justify-center gap-2 shadow-lg active:scale-[0.98] transition-transform"
            >
              {isScanning ? <RefreshCw className="animate-spin" size={20} /> : <Play size={20} />}
              {isScanning ? 'Analyzing & Saving to Cloud...' : 'Run Security Scan'}
            </button>

            {currentResults !== null && (
              <div className="mt-6 border-t border-slate-800 pt-6">
                {currentResults.length === 0 ? (
                  <div className="bg-emerald-900/20 border border-emerald-500/30 rounded-lg p-6 flex flex-col items-center justify-center text-center space-y-2">
                    <ShieldCheck className="text-emerald-400 w-12 h-12" />
                    <p className="font-semibold text-emerald-400">Scan Clean. 0 Threats.</p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    <div className="bg-red-900/20 border border-red-500/30 text-red-400 px-4 py-3 rounded-lg text-sm font-bold flex items-center gap-2">
                      <AlertTriangle size={18} />
                      Found {currentResults.length} Critical Threats
                    </div>
                    {currentResults.map((vuln, idx) => (
                      <div key={idx} className="bg-slate-950 border border-slate-800 rounded-lg p-4">
                        <div className="flex justify-between items-center mb-2">
                          <span className="font-bold text-red-400">{vuln.name}</span>
                          <span className="text-xs bg-red-500/20 text-red-300 px-2 py-1 rounded uppercase font-bold">
                            {vuln.severity}
                          </span>
                        </div>
                        <code className="block w-full bg-black p-2 rounded text-xs text-slate-300 overflow-x-auto border border-slate-800">
                          <span className="text-slate-500 mr-2">{vuln.lineNum} |</span>
                          {vuln.codeSnippet}
                        </code>
                        <button 
  onClick={() => getVulnerabilityAnalysis(vuln.type, vuln.codesnippet)}
  disabled={isAnalyzing}
  className="mt-2 px-3 py-1 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 w-full"
>
  {isAnalyzing ? 'Analyzing...' : 'Generate Fix & Analysis'}
</button>

{analysis && (
  <div className="mt-4 p-4 bg-gray-800 text-gray-100 rounded border border-gray-700 whitespace-pre-wrap font-mono text-sm text-left">
    {analysis}
  </div>
)}

                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* DASHBOARD VIEW */}
        {activeTab === 'dashboard' && (
          <div className="space-y-4 animate-in fade-in duration-300">
            <h2 className="text-xl font-bold flex items-center gap-2 mb-6">
              <Database className="text-emerald-500" /> Cloud Scan History
            </h2>
            
            {scanHistory.length === 0 ? (
              <p className="text-slate-400 text-center py-10">No scans recorded in the database yet.</p>
            ) : (
              scanHistory.map((scan) => (
                <div key={scan.id} className="bg-slate-950 border border-slate-800 rounded-lg p-4 flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      {scan.threatCount > 0 ? (
                        <span className="bg-red-500/20 text-red-400 text-xs font-bold px-2 py-1 rounded flex items-center gap-1">
                          <AlertTriangle size={12} /> {scan.threatCount} Threats
                        </span>
                      ) : (
                        <span className="bg-emerald-500/20 text-emerald-400 text-xs font-bold px-2 py-1 rounded flex items-center gap-1">
                          <ShieldCheck size={12} /> Clean
                        </span>
                      )}
                      <span className="text-slate-400 text-xs flex items-center gap-1">
                        <Clock size={12} />
                        {new Date(scan.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <code className="text-xs text-slate-500 truncate block max-w-[250px] sm:max-w-sm mt-2">
                      {scan.codePreview}
                    </code>
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </main>
    </div>
  );
}

