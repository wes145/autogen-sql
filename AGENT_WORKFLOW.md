# SQL Injection Penetration Testing Agent Workflow

## 🎯 **MISSION: Aggressive Parallel SQL Injection Testing**

This workflow establishes a coordinated approach where **WebPenTester actively explores** while **PlannerBeta tests with BurpSuite simultaneously**.

---

## 📋 **PHASE 1: RAPID DISCOVERY & COORDINATION (PlannerAlpha)**

### **Step 1: Immediate Endpoint Verification**
```
Tool: quick_endpoint_check_tool
Purpose: Instantly verify if login.html, admin.php, etc. exist
Output: Confirmed existing endpoints for immediate testing
```

### **Step 2: Aggressive Discovery Strategy**
```
Tool: aggressive_login_discovery_tool  
Purpose: Generate comprehensive target list + exploration strategy
Output: 
- immediate_test_urls: Ready for BurpSuite
- web_exploration_targets: For WebPenTester clicking
- exploration_strategy: Coordination instructions
```

### **Step 3: Parallel Agent Coordination**
PlannerAlpha issues **simultaneous commands**:

**To WebPenTester:**
```
"@WebPenTester: Start exploring [base_url]. Look for login forms, admin panels, 
and authentication pages. Click through navigation menus, search for 'login', 
'admin', 'signin' links. Report back any forms you find with their URLs."
```

**To PlannerBeta:**
```
"@PlannerBeta: Begin BurpSuite testing on these confirmed endpoints:
- [url]/login.html (if exists)
- [url]/admin.php (if exists)  
- [any_other_confirmed_endpoints]
Start with basic SQL injection payloads while WebPenTester explores."
```

---

## 🌐 **PHASE 2: PARALLEL EXPLORATION (WebPenTester)**

### **Visual Browser Exploration**
- **Headless=False**: Visible browser for monitoring
- **Click Navigation**: Menu items, links, buttons
- **Search Functionality**: Look for search bars, login forms
- **Form Discovery**: Identify input fields, dropdowns, checkboxes
- **Screenshot Capture**: Visual evidence of discovered pages

### **Reporting Protocol**
When WebPenTester finds a form:
```
"Found login form at [full_url]:
- Username field: [field_name]
- Password field: [field_name] 
- Form action: [action_url]
- Method: [GET/POST]
Screenshot captured and saved."
```

---

## 🔧 **PHASE 3: BURPSUITE TESTING (PlannerBeta)**

### **Immediate Testing Strategy**
Start testing **confirmed endpoints** while WebPenTester explores:

**Basic SQL Injection Payloads:**
```
' OR '1'='1
'; DROP TABLE users; --
' UNION SELECT 1,2,3 --
admin'--
```

**Systematic Testing:**
1. **Authentication Bypass**: Login forms
2. **Parameter Injection**: URL parameters, form fields
3. **Error-Based SQL**: Trigger database errors
4. **Union-Based SQL**: Extract data via UNION
5. **Time-Based Blind**: Delayed responses

### **Burp Tools Utilization**
```
- send_http1_request: Manual payload testing
- create_repeater_tab: Save promising requests
- send_to_intruder: Automated payload fuzzing
- get_proxy_http_history: Review captured traffic
```

---

## 🔄 **PHASE 4: DYNAMIC COORDINATION**

### **Information Sharing**
- **WebPenTester → PlannerAlpha**: New form discoveries
- **PlannerAlpha → PlannerBeta**: Additional targets to test
- **PlannerBeta → PlannerAlpha**: Vulnerability confirmations

### **Adaptive Strategy**
If **WebPenTester finds new forms**:
```
1. PlannerAlpha analyzes the form structure
2. PlannerAlpha directs PlannerBeta to test immediately
3. Testing continues in parallel with exploration
```

If **PlannerBeta finds vulnerabilities**:
```
1. Document the successful payload
2. Continue testing other parameters/endpoints
3. Focus on exploitation and data extraction
```

---

## 📊 **PHASE 5: COMPREHENSIVE REPORTING**

### **Vulnerability Documentation**
```json
{
  "target_url": "https://example.com",
  "discovery_method": "aggressive_login_discovery + web_exploration",
  "vulnerable_endpoints": [
    {
      "url": "https://example.com/login.html",
      "parameter": "username",
      "payload": "' OR '1'='1",
      "impact": "Authentication Bypass",
      "evidence": "burp_request_response.txt"
    }
  ],
  "exploration_results": {
    "pages_visited": 15,
    "forms_discovered": 3,
    "screenshots_captured": 8
  }
}
```

---

## 🚨 **CRITICAL SUCCESS FACTORS**

### **1. Parallel Operation**
- WebPenTester and PlannerBeta work **simultaneously**
- No waiting for one agent to complete before starting another
- Continuous communication through PlannerAlpha

### **2. Aggressive Discovery**
- Always include `login.html`, `admin.php` in initial testing
- Use visual browser exploration to find hidden forms
- Test common endpoints even if not found in initial HTML

### **3. Real-Time Adaptation**
- Adjust strategy based on discoveries
- Share information immediately between agents
- Focus testing on most promising targets

### **4. Tool Specialization**
- **PlannerAlpha**: Coordination + Discovery tools only
- **PlannerBeta**: BurpSuite MCP tools exclusively  
- **WebPenTester**: Browser navigation + visual discovery

---

## 🎮 **SELECTOR AGENT RULES**

### **Agent Selection Logic**
```
1. Start: PlannerAlpha (discovery phase)
2. After discovery: SELECT BOTH WebPenTester AND PlannerBeta
3. When WebPenTester reports: PlannerAlpha (analyze findings)
4. When PlannerBeta reports: Continue testing or escalate
5. Final: PlannerAlpha (summary and reporting)
```

### **Termination Conditions**
- All discovered endpoints tested
- Successful SQL injection confirmed
- No new discoveries after comprehensive exploration
- Time/scope limits reached

---

## 🏆 **EXPECTED OUTCOMES**

✅ **Guaranteed login.html discovery** (if it exists)  
✅ **Parallel exploration and testing**  
✅ **Visual confirmation of discovered forms**  
✅ **Comprehensive vulnerability assessment**  
✅ **Detailed exploitation evidence**  

This workflow ensures **no login pages are missed** and maximizes efficiency through **parallel agent operation**. 