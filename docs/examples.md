# Examples

Two walkthroughs that build an application from `cr` commands alone.
Collections and field names are entirely yours; these are conventions, not
built-in types. For a ready-made CRM with schemas, saved views, and a Kanban
pipeline, run the one in [`examples/crm`](../examples/crm/).

## CRM example

A simple CRM can use three collections:

- `companies` for accounts;
- `contacts` for people;
- `deals` for sales opportunities.

### 1. Create a company

```sh
cr create companies acme \
  --set 'name=Acme Corporation' \
  --set 'domain=acme.example' \
  --set 'industry=Manufacturing' \
  --set 'status=customer' \
  --set 'owner.email=sales@example.com' \
  --body 'Strategic account. Renewal is due in December.'
```

### 2. Create a contact and connect them to the company

```sh
cr create contacts jane-doe \
  --set 'name=Jane Doe' \
  --set 'title=VP of Operations' \
  --set 'contact.email=jane@acme.example' \
  --set 'contact.phone=+1-555-0100' \
  --set 'active=true' \
  --body 'Jane is the main buying contact.'

cr link contacts jane-doe company companies acme
```

### 3. Create a deal and add its relationships

```sh
cr create deals acme-renewal-2027 \
  --set 'name=Acme 2027 renewal' \
  --set 'stage=qualification' \
  --set 'value=25000' \
  --set 'currency=USD' \
  --set 'expected_close=2027-12-15' \
  --body 'Confirm seat count before preparing the proposal.'

cr link deals acme-renewal-2027 company companies acme
cr link deals acme-renewal-2027 primary_contact contacts jane-doe
```

### 4. Work with the pipeline

```sh
cr list deals --where 'stage=qualification'
cr search 'seat count' --collection deals --body --ignore-case
cr update deals acme-renewal-2027 --set 'stage=proposal'
cr get deals acme-renewal-2027 --json
cr audit log deals acme-renewal-2027 --limit 10
```

### 5. Close or remove the deal

Mark it won while retaining the record:

```sh
cr update deals acme-renewal-2027 \
  --set 'stage=won' \
  --set 'closed_at=2027-11-30'
```

Or delete a test or duplicate deal:

```sh
cr delete deals duplicate-deal --yes
```

## ATS example

An ATS can use three collections:

- `candidates` for people;
- `roles` for job openings;
- `applications` for a candidate's progress through one role.

Keeping stage on an application is useful because one candidate can apply for multiple roles.

### 1. Create a role

```sh
cr create roles senior-rust-engineer \
  --set 'title=Senior Rust Engineer' \
  --set 'department=Engineering' \
  --set 'location=Remote - Europe' \
  --set 'status=open' \
  --set 'headcount=1' \
  --body 'Looking for production Rust and distributed systems experience.'
```

### 2. Create a candidate

```sh
cr create candidates alex-smith \
  --set 'name=Alex Smith' \
  --set 'contact.email=alex@example.com' \
  --set 'location=Amsterdam' \
  --set 'skills=[Rust, PostgreSQL, distributed systems]' \
  --set 'source=referral' \
  --body 'Strong infrastructure background. Referred by Sam.'
```

### 3. Create an application and connect it

```sh
cr create applications alex-smith-senior-rust \
  --set 'stage=applied' \
  --set 'applied_at=2026-08-03' \
  --set 'owner.email=recruiter@example.com' \
  --body 'Resume received. Schedule the recruiter screen.'

cr link applications alex-smith-senior-rust candidate candidates alex-smith
cr link applications alex-smith-senior-rust role roles senior-rust-engineer
```

### 4. Move the application through the hiring process

```sh
cr update applications alex-smith-senior-rust --set 'stage=recruiter_screen'
cr update applications alex-smith-senior-rust --set 'stage=technical_interview'
cr list applications --where 'stage=technical_interview' --json
cr search 'distributed systems' --collection candidates --ignore-case --json
cr get applications alex-smith-senior-rust --json
```

Record an offer or rejection:

```sh
cr update applications alex-smith-senior-rust \
  --set 'stage=offer' \
  --set 'offer.sent_at=2026-09-15'
```

Or:

```sh
cr update applications alex-smith-senior-rust \
  --set 'stage=rejected' \
  --set 'rejection.reason=Role requires a different time zone'
```

Review the complete history:

```sh
cr audit log applications alex-smith-senior-rust --limit 20 --json
```

Next, [add a schema](schemas.md) to restrict each collection's fields, or
[serve the database](web-ui.md) to work with it in a browser.
