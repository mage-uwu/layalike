"""Three policies and hand-labeled cases for comparing ways of making policy decisions with Laya.

Each case labels the truth of every condition (None where the text leaves it genuinely open and
the rules do not need it). The correct decision is never written by hand: it is the policy run on
those labels, so a case cannot disagree with its own policy.
"""

SECURITY = {
    "name": "security_triage",
    "question": "What should the security team do about this alert?",
    "descriptions": {
        "contain": "isolate the host or disable the account right now",
        "investigate": "look into it further before acting",
        "close": "benign or expected activity, close the alert",
    },
    "conditions": {
        "authorized": "Is the activity explicitly authorized, scheduled or approved, such as a pentest, a known scanner, a backup job or planned maintenance?",
        "stolen_creds": "Is there evidence that an account's credentials were stolen or used by someone other than their owner?",
        "malware": "Is there evidence of malware or ransomware running on a host?",
        "exfiltration": "Is data being sent to an outside destination without authorization?",
        "suspicious": "Is there any unusual or suspicious activity?",
    },
    "rules": [
        {"if": "malware or ((stolen_creds or exfiltration) and not authorized)", "then": "contain"},
        {"if": "suspicious and not authorized", "then": "investigate"},
    ],
    "default": "close",
}

SECURITY_CASES = [
    ("14 failed logins for admin@corp, then a successful login from a new country at 03:12, then a mailbox rule forwarding all mail to an external address was created.",
     dict(authorized=False, stolen_creds=True, malware=False, exfiltration=True, suspicious=True)),
    ("Scheduled vulnerability scanner 10.0.4.12 performed a port sweep of the DMZ during the approved Tuesday maintenance window.",
     dict(authorized=True, stolen_creds=False, malware=False, exfiltration=False, suspicious=None)),
    ("EDR: a process on FIN-WS-22 is encrypting files in the shared drive and has written README_RESTORE_FILES.txt into every folder.",
     dict(authorized=False, stolen_creds=False, malware=True, exfiltration=None, suspicious=True)),
    ("During this week's approved penetration test, the contracted testers logged in to the test account qa-user with a password they had cracked.",
     dict(authorized=True, stolen_creds=True, malware=False, exfiltration=False, suspicious=None)),
    ("User jsmith uploaded 40 GB of customer database exports to a personal Dropbox account at 2 a.m.",
     dict(authorized=False, stolen_creds=False, malware=False, exfiltration=True, suspicious=True)),
    ("A user reported a phishing email. Nobody clicked the link and the mail gateway quarantined the message.",
     dict(authorized=False, stolen_creds=False, malware=False, exfiltration=False, suspicious=True)),
    ("The nightly backup job copied the finance share to the offsite backup vault as scheduled.",
     dict(authorized=True, stolen_creds=False, malware=False, exfiltration=False, suspicious=False)),
    ("Service account svc-deploy logged in from an IP address never seen before, at an unusual hour. MFA passed and there was no further activity.",
     dict(authorized=False, stolen_creds=False, malware=False, exfiltration=False, suspicious=True)),
    ("Antivirus detected a trojan in an email attachment on HR-LAPTOP-7 and quarantined it before it was ever opened or executed.",
     dict(authorized=False, stolen_creds=False, malware=False, exfiltration=False, suspicious=True)),
    ("An IT admin applied OS patches to the web servers during approved change window CHG-1182 and the servers rebooted.",
     dict(authorized=True, stolen_creds=False, malware=False, exfiltration=False, suspicious=False)),
    ("A user says her password stopped working. Logs show it was changed from a Tor exit node, and whoever changed it then read her inbox.",
     dict(authorized=False, stolen_creds=True, malware=False, exfiltration=None, suspicious=True)),
    ("CPU on the build server spiked to 100% at 01:00, caused by the regular nightly compile job.",
     dict(authorized=True, stolen_creds=False, malware=False, exfiltration=False, suspicious=False)),
]

REFUNDS = {
    "name": "refunds",
    "question": "How should support resolve this refund request?",
    "descriptions": {
        "escalate": "hand it to a senior agent",
        "refund": "give a full refund",
        "partial_credit": "give a partial store credit",
        "deny": "politely decline the refund",
    },
    "conditions": {
        "legal_threat": "Does the customer threaten legal action, a chargeback, or a complaint to a regulator?",
        "duplicate_charge": "Was the customer charged more than once for the same purchase?",
        "service_failure": "Did the product or service fail, break, or not arrive as promised?",
        "recent": "Was the purchase made within the last 30 days?",
    },
    "rules": [
        {"if": "legal_threat", "then": "escalate"},
        {"if": "duplicate_charge", "then": "refund"},
        {"if": "service_failure and recent", "then": "refund"},
        {"if": "service_failure", "then": "partial_credit"},
    ],
    "default": "deny",
}

REFUND_CASES = [
    ("I was charged twice for my annual plan this morning. Please refund the duplicate.",
     dict(legal_threat=False, duplicate_charge=True, service_failure=False, recent=True)),
    ("I bought the blender last week and it won't turn on at all.",
     dict(legal_threat=False, duplicate_charge=False, service_failure=True, recent=True)),
    ("The headphones I bought in January stopped charging. It's June now.",
     dict(legal_threat=False, duplicate_charge=False, service_failure=True, recent=False)),
    ("I just don't like the color of the jacket I bought 5 days ago. I want my money back.",
     dict(legal_threat=False, duplicate_charge=False, service_failure=False, recent=True)),
    ("You charged me twice, and if this isn't fixed today I'm filing a chargeback with my bank.",
     dict(legal_threat=True, duplicate_charge=True, service_failure=False, recent=None)),
    ("The package from my order three weeks ago never arrived. Tracking has been stuck for days.",
     dict(legal_threat=False, duplicate_charge=False, service_failure=True, recent=True)),
    ("I subscribed two months ago. The app has been down for the last four days and I couldn't use it.",
     dict(legal_threat=False, duplicate_charge=False, service_failure=True, recent=False)),
    ("I'll be reporting you to the consumer protection bureau. The laptop I bought yesterday arrived cracked.",
     dict(legal_threat=True, duplicate_charge=False, service_failure=True, recent=True)),
    ("I bought this course last year and never got around to it. Can I get a refund?",
     dict(legal_threat=False, duplicate_charge=False, service_failure=False, recent=False)),
    ("My card statement shows the same $49.99 charge from you twice on March 3.",
     dict(legal_threat=False, duplicate_charge=True, service_failure=False, recent=None)),
    ("The printer I ordered 10 days ago works fine, but I found it cheaper somewhere else.",
     dict(legal_threat=False, duplicate_charge=False, service_failure=False, recent=True)),
    ("I ordered a size M shirt two weeks ago and received a size XL instead.",
     dict(legal_threat=False, duplicate_charge=False, service_failure=True, recent=True)),
]

GAME = {
    "name": "minecraft_agent",
    "question": "What should the player do next?",
    "descriptions": {
        "flee": "run away from danger",
        "fight": "attack the hostile mob",
        "eat": "eat some food",
        "mine": "mine the ore",
        "explore": "keep exploring",
    },
    "conditions": {
        "hostile_near": "Is a hostile mob such as a zombie, skeleton, creeper or spider close to the player?",
        "low_health": "Is the player's health low, below about a third of full?",
        "has_weapon": "Does the player have a sword, axe, bow or other weapon?",
        "hungry": "Is the player hungry, with the food bar low?",
        "ore_visible": "Is ore such as coal, iron, gold or diamond visible nearby?",
    },
    "rules": [
        {"if": "hostile_near and (low_health or not has_weapon)", "then": "flee"},
        {"if": "hostile_near", "then": "fight"},
        {"if": "hungry", "then": "eat"},
        {"if": "ore_visible", "then": "mine"},
    ],
    "default": "explore",
}

GAME_CASES = [
    ("Health 18/20. Food 19/20. Holding a diamond sword. A zombie is 3 blocks away and approaching.",
     dict(hostile_near=True, low_health=False, has_weapon=True, hungry=False, ore_visible=False)),
    ("Health 4/20. Food 15/20. Holding an iron sword. A skeleton is shooting at the player from 5 blocks away.",
     dict(hostile_near=True, low_health=True, has_weapon=True, hungry=False, ore_visible=False)),
    ("Health 20/20. Food 20/20. Inventory: dirt, cobblestone, torches. A creeper is hissing right next to the player.",
     dict(hostile_near=True, low_health=False, has_weapon=False, hungry=False, ore_visible=False)),
    ("Health 20/20. Food 3/20. Inventory: stone pickaxe, 5 cooked beef. No mobs around. Iron ore in the wall.",
     dict(hostile_near=False, low_health=False, has_weapon=None, hungry=True, ore_visible=True)),
    ("Health 16/20. Food 18/20. Standing in a cave with coal ore and iron ore visible on the wall. It's quiet.",
     dict(hostile_near=False, low_health=False, has_weapon=None, hungry=False, ore_visible=True)),
    ("Health 20/20. Food 20/20. Open plains in daylight, nothing in sight.",
     dict(hostile_near=False, low_health=False, has_weapon=None, hungry=False, ore_visible=False)),
    ("Health 6/20. Food 4/20. No mobs nearby. Inventory: bread, wooden sword.",
     dict(hostile_near=False, low_health=True, has_weapon=True, hungry=True, ore_visible=False)),
    ("The player is badly hurt, nearly dead, and a spider is lunging at them. They are carrying a bow.",
     dict(hostile_near=True, low_health=True, has_weapon=True, hungry=None, ore_visible=False)),
    ("Full health, well fed, carrying an iron axe. A zombie is wandering about 40 blocks away across the river.",
     dict(hostile_near=False, low_health=False, has_weapon=True, hungry=False, ore_visible=False)),
    ("Health 14/20. Food 17/20. Holding an iron sword. Diamonds glitter in the cave ahead, and two skeletons stand right next to the player.",
     dict(hostile_near=True, low_health=False, has_weapon=True, hungry=False, ore_visible=True)),
    ("Health 20/20 but starving, food 1/20. A spider is attacking. Sword in hand.",
     dict(hostile_near=True, low_health=False, has_weapon=True, hungry=True, ore_visible=False)),
    ("Health 19/20. Food 12/20. Empty hands. Gold ore visible just below. No mobs.",
     dict(hostile_near=False, low_health=False, has_weapon=False, hungry=False, ore_visible=True)),
]

SUITES = [(SECURITY, SECURITY_CASES), (REFUNDS, REFUND_CASES), (GAME, GAME_CASES)]
