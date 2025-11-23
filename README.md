# Tsunagu 🦦

**Connecting people when depression makes it hardest to reach out.**

Tsunagu (つなぐ - "to connect") is a mental health support app that removes the barrier of asking for help. Like otters holding hands so they don't drift apart, Tsunagu keeps you connected to the people who care about you.

---

## The Problem

Depression makes asking for help nearly impossible. People struggle with executive dysfunction, guilt about burdening others, and difficulty articulating their needs—even when they recognize they need support.

## The Solution

Instead of waiting for someone to reach out, Tsunagu **proactively alerts their support network** when patterns suggest they might need help.

- **Simple daily check-ins** (one-tap mood tracking)
- **Pattern detection** (3+ bad days, withdrawal signs)
- **Proactive supporter prompts** (supporters reach out first)
- **Pre-written help requests** (for user-initiated contact)
- **Full transparency** (users see when/why supporters were notified)

### Why This Works

Research on 176+ mental health app studies shows:
- Human support is the most effective engagement strategy
- People with depression struggle to initiate contact
- Proactive outreach beats waiting for users to act
- Simple mood monitoring + human connection = best outcomes

Most mental health apps wait for the user to act. Tsunagu flips this: **supporters act first** based on pattern detection, removing the burden from the person least able to carry it.

---

## Tech Stack

**Frontend:** React, Tailwind CSS, Axios  
**Backend:** Django + Django REST Framework, PostgreSQL  
**Background Jobs:** Django-Q for pattern detection & notifications  
**Deployment:** Vercel (frontend), Railway (backend)

---

## Key Features

- One-tap daily mood check-in (👍 😐 👎)
- Support network setup with privacy controls
- Proactive supporter notifications when patterns detected
- Pre-written help request templates
- Check-in history and pattern visualization
- Email notifications with actionable guidance for supporters

---

## Design Philosophy

1. **Remove burden, don't add it** - Every action ≤3 taps
2. **Proactive support > reactive waiting** - Supporters initiate contact
3. **Human connection > data collection** - Facilitate support, not track metrics
4. **Transparent > mysterious** - Users see what the system does
5. **Privacy first** - User controls all data sharing
6. **No gamification** - Research shows it increases dropout rates

---

## Why I Built This

Built for family members with depression who struggle to ask for help. The core insight: the biggest barrier isn't lack of support—it's the impossibility of asking for it when you need it most.

By having supporters reach out based on simple pattern detection, we remove that barrier entirely.

---

## Important Notes

**Tsunagu is not a replacement for therapy or professional care.** It's a tool to facilitate human connection and works best alongside professional treatment.

**Crisis Resources:**  
- 988 Suicide & Crisis Lifeline  
- Crisis Text Line: Text HOME to 741741

---

## Roadmap

**Current (MVP):** User auth, daily check-ins, support network, proactive prompts, help requests, pattern detection  
**Phase 2:** AI-enhanced message generation (Claude API), sentiment analysis, activity tracking  
**Phase 3:** Therapy prep tools, supporter dashboard, SMS notifications

---

*"Like otters holding hands, Tsunagu keeps you connected when depression tries to pull you away."* 🦦

Built with 💙 by Takara | [LinkedIn](your-link) | [Portfolio](your-link)
