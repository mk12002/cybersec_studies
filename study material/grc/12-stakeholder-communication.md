# Module 12 — Stakeholder Communication

Technical knowledge of frameworks and testing means little if you can't extract the right information from stakeholders, navigate resistance, and document outcomes clearly. This module is a practical communication playbook for audit/GRC work — and it's a skill set that translates directly to your stated strength in stakeholder pitches and CXO-facing documentation.

## 1. How to Conduct Calls (Walkthroughs and Evidence Discussions)

### Before the Call
- Review whatever documentation already exists (prior year workpapers, policy documents, the RCM) so you're not asking the stakeholder to explain things you could have learned beforehand — this respects their time and builds credibility immediately.
- Prepare a structured list of questions, but hold them loosely — the best walkthrough calls feel like a guided conversation, not an interrogation script read verbatim.
- Send an agenda in advance for anything beyond a quick clarification, so the right person attends and comes prepared.

### During the Call
- Start by stating the **purpose and scope** of the call clearly, so the stakeholder isn't guessing what you're trying to learn.
- Ask **open-ended questions first** ("Walk me through what happens when a new employee joins") before narrowing to specifics — this surfaces information you didn't know to ask about directly.
- **Listen for what's NOT said** — gaps, hesitations, or vague answers ("usually," "I think," "someone handles that") are signals worth following up on, since precise processes get described precisely by people who actually do them regularly.
- Take detailed notes, including direct quotes for anything that will become evidence of process understanding (useful to cite back during issue discussion if there's later disagreement about what was actually said).
- Confirm understanding by **summarizing back** what you heard before ending the call ("So to confirm: HR creates the record, then the system auto-generates the access request, then IAM provisions — did I get that right?").

### After the Call
- Send a brief written summary/confirmation, especially for anything that will inform your testing conclusions — this creates a paper trail and gives the stakeholder a chance to correct any misunderstanding promptly, before it propagates into testing.

## 2. Questions to Ask (by Purpose)

### Process Understanding Questions
- "Walk me through this process step by step, from trigger to completion."
- "Who is involved at each step, and what's their specific responsibility?"
- "What system(s) are used, and where does the evidence/record live?"
- "What happens if something goes wrong at this step — is there an exception process?"

### Control Design Probing Questions
- "What would happen if [the control owner] made a mistake here — would anything catch it?" (probing for a detective/compensating control)
- "Has this process changed at all during the period we're testing?" (critical — if the process changed mid-period, you may need to test both the old and new versions separately)
- "Who has the technical ability to do this, even if they're not supposed to?" (probing for access/SoD gaps the documented process doesn't address)

### Evidence-Specific Questions
- "Can you show me where this is recorded in the system, rather than describing it to me?" (moving from inquiry to observation/inspection — Module 9)
- "Is this report manually compiled or system-generated?" (Module 8's evidence quality distinction)
- "Who else, besides you, could pull this same report and get the same result?" (probing for whether the evidence is independently verifiable)

## 3. Handling Difficult Stakeholders

Audit work is inherently a bit adversarial by structural design — you're independently verifying someone else's work, sometimes finding gaps in something they're personally responsible for. Some friction is normal and not a sign you're doing something wrong; the goal is to manage it professionally, not to eliminate it entirely.

### Common Difficult Stakeholder Patterns and How to Handle Them

**The Defensive Stakeholder** (reacts to questions as personal criticism)
- Reframe explicitly: "This isn't about you personally — I'm required to independently verify this for every control, regardless of who owns it." Keep tone factual and calm; defensiveness often de-escalates faster when met with consistent neutrality rather than matched energy.

**The Stonewaller** (delays evidence, gives vague non-answers, avoids scheduling calls)
- Document every request and its timeline in writing (this protects you and creates an evidence trail of the delay itself, which can become relevant if the delay itself needs escalating).
- Escalate through proper channels (your manager, the engagement lead) rather than unilaterally — but don't wait too long to escalate either; chronic delays threaten the entire engagement timeline and it's better to flag early than to absorb the risk silently.

**The Over-Explainer** (buries simple answers in excessive context, possibly to obscure a gap)
- Politely redirect: "That's helpful context — can we come back to the specific question of [X]?" Don't be afraid to ask the same precise question twice if the first answer didn't actually address it.

**The "Trust Me" Stakeholder** (resists providing evidence, insists the control "just works")
- Stay firm but professional: "I believe you, and this is exactly why I need to document the evidence — it protects both of us if this is ever questioned later by [external auditors/regulators/the audit committee]." Framing evidence requests as protective rather than accusatory often reduces resistance.

**The Stakeholder Who Disputes a Finding**
- Listen fully to their counterpoint first — sometimes they're right and you're missing context, and a good auditor updates their conclusion when presented with valid new evidence (this is a strength, not a weakness, to demonstrate).
- If after listening you still believe the finding stands, restate the specific evidence and criteria (Module 10) that support it, factually and without becoming defensive yourself.
- If genuinely unresolved, escalate to your engagement lead/manager for a second opinion rather than letting it become a prolonged one-on-one standoff.

## 4. Evidence Follow-Up

A huge proportion of real-world audit friction is simply chasing incomplete or wrong evidence. A few practical habits:

- **Acknowledge receipt immediately**, even if you haven't reviewed it yet — silence makes stakeholders anxious and prone to over-following-up themselves.
- **Be specific about gaps**, not just "this isn't sufficient" — say exactly what's missing ("This shows the approval, but I also need the system log showing when the account was actually disabled, with a timestamp").
- **Set a clear new deadline** for the follow-up, don't leave it open-ended.
- **Track follow-ups centrally** (the PBC list from Module 11) so nothing falls through the cracks across multiple concurrent requests.

## 5. Escalation

Knowing **when** and **how** to escalate is itself a professional skill, not a sign of failure.

### When to Escalate
- Evidence requests are significantly overdue with no clear resolution path.
- A stakeholder is being uncooperative in a way that threatens the engagement timeline or scope.
- You discover something during fieldwork that suggests a risk significant enough that it shouldn't wait for the final report (e.g., evidence of active fraud, an active unaddressed security compromise) — these require **immediate** escalation outside normal reporting cadence.
- You and the stakeholder have a genuine, unresolved disagreement about a finding's validity after good-faith discussion.

### How to Escalate Well
- Escalate to the right level first (your direct manager/engagement lead) before jumping further up, unless the situation is urgent enough to warrant immediate higher escalation (e.g., active fraud/security incident).
- Bring **facts and documentation**, not just frustration — "I requested X on [date], followed up on [date], and as of today have not received a response" is far more effective than "they're not cooperating."
- Stay solution-oriented — escalation should come with a proposed path forward, not just a problem dump.

## 6. Documentation

Every meaningful stakeholder interaction relevant to the audit should leave a written trace — this isn't bureaucratic box-checking, it's the practical backbone of audit defensibility (if your conclusions are ever challenged later, your documentation is what supports them).

### What to Document
- Meeting notes/summaries (formal or informal, depending on significance).
- Email confirmations of key process understanding.
- Evidence request timelines and any delays/escalations.
- Any verbal commitments from stakeholders (e.g., remediation timelines) — get these in writing promptly after they're made verbally.

## 7. Meeting Minutes

For formal sessions (kickoff meetings, issue discussion meetings, CAB-adjacent calls), structured minutes typically capture:
- Date, attendees, and their roles.
- Topics discussed.
- Decisions made.
- Action items, with clear owners and due dates.
- Next steps/next meeting (if applicable).

Minutes should be **circulated promptly** after the meeting (ideally within 24 hours) while details are fresh and while there's still time for attendees to flag any inaccuracy before the minutes become the official record.

---
**Quick Self-Check Questions**
1. Why is "listening for what's NOT said" often more revealing than the literal answer to a walkthrough question?
2. Describe the difference in approach between handling a "Defensive Stakeholder" and a "Stonewaller" — why do these require different tactics?
3. Why should evidence-related communication frame requests as "protective" rather than "accusatory," and when does this framing genuinely help?
4. What specific situations warrant immediate escalation outside the normal reporting cadence, and why?
5. Why is it important to circulate meeting minutes within 24 hours rather than at the end of the engagement?
