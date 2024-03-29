#require ["fileinto", "reject", "vacation", "notify", "envelope", "body", "relational", "regex", "subaddress", "copy", "mailbox", "mboxmetadata", "servermetadata", "date", "index", "comparator-i;ascii-numeric", "variables", "imap4flags", "editheader", "duplicate", "vacation-seconds", "fcc", "vnd.cyrus.jmapquery", "vnd.cyrus.log", "mailboxid", "special-use", "vnd.cyrus.snooze", "vnd.cyrus.imip"];

# Rule Skip - Contacts (but not auto-saved contacts)

if 
    jmapquery text:
  {
     "conditions" : [
        {
           "fromAnyContact" : true
        },
        {
           "conditions" : [
              {
                 "fromContactGroupId" : "<AUTOSAVED CONTACT GROUP ID>"
              }
           ],
           "operator" : "NOT"
        }
     ],
     "operator" : "AND"
  }
.
{
  set "flagged" "Y";
  stop;  
}

# Rule Skip rules - notifications [regular expressions + from]
if 
    anyof(
    header :regex "Subject" "(?i)\\b(PIN|Verify|Verification|Confirm|One-Time|Single(-|\\s)Use)\\b.*?(passcode|number|code.*$)",
    header :regex "Subject" "(?i)^.*upcoming (appointment|visit).*",
    header :regex "Subject" "(?i)^.*new.*(sign(in|-in|ed)|(log(in|-in|ged)))",
    header :regex "Subject" "(?i)^.*(meeting|visit|appointment|event).*\\b(reminder|notification)",
    header :regex "Subject" "(?i)^.*verify.*(device|email|phone)",
    header :regex "Subject" "(?i)^.*Apple.*(ID was used to sign in)",
    header :regex "Subject" "(?i)^.*(computer|phone|device).*(added)",
    header :regex "Subject" "(?i)^2FA.*(turned on)",
    header :regex "Subject" "(?i)^.*confirm.*(you)",
    header :regex "Subject" "(?i)^.*you.*((log|sign)\\s?-?\\s?in).*$",
    header :regex "Subject" "(?i)^.*sign.*(in)"
    )
{
  stop;
}

# Rule Alerts [regular expressions]

if 
    anyof(
    header :regex "Subject" "(?i)^(.*dependabot|.*security|.*advisor).*$",
    header :regex "Subject" "\\b(?i)(uptime|downtime|outage|alert|PagerDuty).*\\b",
    header :regex "Subject" "^(\\[URGENT\\] )?Certificate (discovered|expiration) for (.+?)(?: and \\d+ other hosts)?(?: \\((\\d{2} \\w+ \\d{4})\\))?(\\s*\\[URGENT\\])?$"
    )
{
    fileinto "INBOX.Notifications";
    setflag "\\Seen";
}

# Rule Forward - Reader [regular expression]

if 
    anyof(
    header :regex "List-Id" "(?!www\\.)([a-zA-Z0-9-]+)\\.substack\\.com",
    header :regex "List-Id" "[a-zA-Z0-9-]+\\.buttondown\\.email"
    )
{
  setflag "\\Seen";
  fileinto "INBOX.Forwarded.Reader";
  #redirect :copy "<YOUR_READER_EMAIL>"; #analyze, then remove comment
  stop;
}

# Rule Deliveries - no forward [regular expressions + glob patterns]

if 
    anyof(
    address :regex "From" "usps|fedex|narvar|shipment-tracking|getconvey",
    header :regex "From" "(^|,)[[:space:]]*\"?.?\\(ed.*x delivery manager\\|.*ed.*x\\.com\\|tracking.*updates.*\\)\"?[[:space:]]*<",
    header :regex "Subject" "(?i)^.*package (has been?|was) delivered.*$"
    )
{
    fileinto "INBOX.Financial.Deliveries";
    stop;
}

# Rule Deliveries [regular expressions]

if 
allof (
    anyof(
        header :regex "Subject" "(?i)(ship(ped)?)|(.*a shipment (from|to).*(was|has) shipped.*)|((package|order) (is|has))|(track(ing)? .* your)"
    ),
    anyof(
    body :regex "(1Z)[0-9A-Z]{16}",
    body :regex "(T)+[0-9A-Z]{10}",
    body :regex "[0-9]{9}",
    body :regex "[0-9]{26}",
    body :regex "(94|93|92|94|95)[0-9]{20}",
    body :regex "(94|93|92|94|95)[0-9]{22}",
    body :regex "(70|14|23|03)[0-9]{14}",
    body :regex "(M0|82)[0-9]{8}",
    body :regex "([A-Z]{2})[0-9]{9}([A-Z]{2})",
    body :regex "[0-9]{20}",
    body :regex "[0-9]{15}",
    body :regex "[0-9]{12}",
    body :regex "[0-9]{22}"
    )
)
{
    setflag "\\Seen";
    fileinto "INBOX.Financial.Deliveries";
    #redirect :copy "<YOURPACKAGETRACKINGEMAIL>"; #analyze, then remove comment
    stop;
}

# Rule Financial - promotions [regular expressions]
if 
    anyof(
    address :regex "From" "(^.*store-news.*$|^.*axxess.*$)(\\b.*?|$)",
    header :regex "Subject" "^(?=.*\\b(?i)(final offer|limited time|last chance|black friday|cyber monday|holiday|christmas|free shipping|send (gift|present))\\b).*\\b(?i)(discount|save|\\d+% off|free)\\b",
    body :text :regex "\\b\\d{1,2}(?:\\.\\d+)?% off\\b",
    header :regex "Subject" "\\b(?i)(discount(ed)?|save|\\d+% off|free)\\b"
    )
{
    fileinto "INBOX.Financial.Promotions";
    stop;
}

# Rule Financial - travel forward [regular expressions]
if 
    header :regex "Subject" "\\b(?i)(flight|confirmation|you're going to).*\\b(reservation|on)\\b"
{
    setflag "\\Seen";
    fileinto "INBOX.Financial.Travel";
    #redirect :copy "track@my.flightyapp.com";
    stop;
}

# Rule Financial - travel [regular expressions]
if 
    anyof(
    header :regex "Subject" "\\b(?i)(hotel|reservation|booking|dining|restaurant|travel)(s)?( |-)?(confirmation|reservations?|bookings?|details)\\b",
    header :regex "Subject" "\\b(?i)(uber|lyft|rideshare)(s)?( |-)?(receipt|confirmation|ride summary|your ride with)\\b"
    )
{
    fileinto "INBOX.Financial.Travel";
    stop;
}


# Rule Financial - tickets [regular expressions]
if 
    header :regex "Subject" "\\b(?i)(concert|event|show|performance|ticket|admission|venue|registration)\\b"
{
    fileinto "INBOX.Financial.Tickets";
    stop;
}

# Rule Financial - media [regular expressions]
# TODO: change to use header detection, rather than From search

if 
    address :regex "From" "^(?i:Disneyplus.*$|Netflix.*$|^.*hulu.*$|HBOmax.*$|MoviesAnywhere.*$|iTunes.*$|7digital.*$|Bandcamp.*$|Roku.*$|Plex.*$|Peacock.*$|Peacocktv.*&)"
{
    setflag "\\Seen";
    
    fileinto "INBOX.Financial.Media";
    stop;
}

# Rule Financial - taxes [regular expressions]

if 
    header :regex "Subject" "\\b(?i)(tax|taxes|taxation)(es)?( |-)?(year|years|season|deadline|form|return|refund|filing|audit|documents?)\\b(\\d{4})?"
{
    setflag "\\Seen";

    fileinto "INBOX.Financial.Taxes";
    stop;
}

# Rule Financial [regular expressions + globs]
if 
    anyof(
    body :text :regex "(?i)you(?:r)?[\\s-]*(?:pre[\\s-]?order|pre[\\s-]?order(?:ed))",
    header :regex ["To","Cc"] "(^|,)[[:space:]]*\"?.*\\[Aa\\]\\[Pp\\]\\[Pp\\]\\[Ll\\]\\[Ee\\] \\[Cc\\]\\[Aa\\]\\[Rr\\]\\[Dd\\].*\\[Ss\\]\\[Uu\\]\\[Pp\\]\\[Pp\\]\\[Oo\\]\\[Rr\\]\\[Tt\\].*\"?[[:space:]]*<",
    header :regex "Subject" "(?i)\\b(receipt|bill|invoice|transaction|statement|payment|order|subscription|authorized|booking|renew(al|ing)?|expir(e|ed|ing)?|deposit|withdrawal|purchased?|(itunes|apple) store|credit (score|report)|manage (account|loan))\\b.*",
    header :regex "Subject" "(?i)\\b(gift (card|certificate)|zelle|new plan|autopay)\\b.*",
    header :regex "Subject" "(?i).* paid .* \\$(\\d,?)+\\.\\d{2}"
    )
{
    fileinto "INBOX.Financial";
    stop;
}

# Rule Notifications - privacy [regular expressions]
if 
    header :regex "Subject" "\\b(?i)(CCPA|California Consumer Privacy Act|privacy request|data privacy|personal data request|rights request)\\b"
{
    setflag "\\Seen";
    fileinto "INBOX.Notifications.Privacy";
    stop;
}

# Rule DMARC [regular expressions]
if 
    anyof(
    header :regex "Subject" "((^.*dmarc.*$)(\\b.*?|$))",
    address :regex "From" "((^.*dmarc.*$)(\\b.*?|$))"
    )
{
    setflag "\\Seen";
    fileinto "INBOX.Notifications.DMARC";
    stop;
}

# Rule Notifications - customer support [glob patterns]
if 
    anyof (
        header :regex "From" "(^|,)[[:space:]]*\"?.*customer.*.?\\(are\\|uccess\\|upport\\)\"?[[:space:]]*<",
        header :regex "Subject" "(?i)(\\b(feedback|opinion).*review)|(\\breview.*(experience|order|purchase))|(\\b(leave|write)\\b.*review)|(\\bshare|love (your|some) (thoughts|feedback|experience))"
    )
{
    fileinto "INBOX.Notifications";
    stop;
}

# Rule Notifications [regular expressions]
if 
    anyof(
    header :regex "Subject" "\\b((?i:Privacy|User).*((?i:Policy|Agreement).*$)|(?i:Protect|Register|Update).*((?i:Your Account).*$))",
    header :regex "Subject" "\\b((?i:Important|Critical).*((?i:Account|Plan).*(?i:Information|Updates))|^.*(?i:Failed|Unsuccessful).*(?i:Deployment)(\\b.*?|$))",
    header :regex "Subject" "^.*((?i:Google Account)).*((?i:Inactive|Closed|Settings))(\\b.*?|$)",
    header :regex "Subject" "^.*((?i:Weekly|Monthly).*(?i:Report|Update))(\\b.*?|$)"
    )

{
    setflag "\\Seen";
    fileinto "INBOX.Notifications";
    stop;
}

# Rule Github [mailing list id]
if 
    header :regex "List-ID" ".*github\\.com"
{
    fileinto "INBOX.Notifications.Github";
    stop;
}

# Rule Social [from targeting]
# Search: "from:facebook.com OR from:twitter.com OR from:linkedin.com OR from:tumblr.com"
if 
    anyof(
    address :contains "From" "twitter.com",
    address :contains "From" "facebook.com",
    address :contains "From" "linkedin.com",
    address :contains "From" "tumblr.com"
    )
{
    fileinto "INBOX.Social";
    stop;
}

# Rule Newsletters [list-unsubscribe]
if 
    exists "List-Unsubscribe"
{
    fileinto "INBOX.Newsletters";
    stop;
}
