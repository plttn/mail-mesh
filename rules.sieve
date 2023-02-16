# New sieve rules

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
    addflag "\\Seen";
}

# Rule Forward - Reader [regular expression]

if 
    anyof(
    header :regex "List-Id" "(?!www\\.)([a-zA-Z0-9-]+)\\.substack\\.com",
    header :regex "List-Id" "[a-zA-Z0-9-]+\\.buttondown\\.email"
    )
{
  fileinto "INBOX.Forwarded.Reader";
  #redirect :copy "<READER FORWARD EMAIL>"; #analyze, then remove comment
  addflag "\\Seen";
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
        header :regex "Subject" "(?i)(ship(ped)?)|(.*a shipment (from|to).*(was|has) shipped.*)|((package|order) (is|has))|(track(ing)? .* your)",
    ),
    anyof(
    body :text :regex "\\s(1Z)[0-9A-Z]{16}\\s",
    body :text :regex "\\s(T)+[0-9A-Z]{10}\\s",
    body :text :regex "\\s[0-9]{9}\\s",
    body :text :regex "\\s[0-9]{26}\\s",
    body :text :regex "\\s(94|93|92|94|95)[0-9]{20}\\s",
    body :text :regex "\\s(94|93|92|94|95)[0-9]{22}\\s",
    body :text :regex "\\s(70|14|23|03)[0-9]{14}\\s",
    body :text :regex "\\s(M0|82)[0-9]{8}\\s",
    body :text :regex "\\s([A-Z]{2})[0-9]{9}([A-Z]{2})\\s",
    body :text :regex "\\s[0-9]{20}\\s",
    body :text :regex "\\s[0-9]{15}\\s",
    body :text :regex "\\s[0-9]{12}\\s",
    body :text :regex "\\s[0-9]{22}\\s"
    )
)
{
    fileinto "INBOX.Financial.Deliveries";
    #redirect :copy "<PACKAGE FORWARD EMAIL>"; #analyze, then remove comment
    addflag "\\Seen";
    stop;
}

# Rule Financial - promotions [regular expressions]
if 
    anyof(
    address :regex "From" "(^.*store-news.*$|^.*axxess.*$)(\\b.*?|$)",
    header :regex "Subject" "^(?=.*\\b(?i)(final offer|limited time|last chance|black friday|cyber monday|holiday|christmas|free shipping|send (gift|present))\\b).*\\b(?i)(discount|save|\\d+% off|free)\\b",
    body :text :regex "\\b\\d{1,2}(?:\\.\\d+)?% off\\b"
    )
{
    fileinto "INBOX.Financial.Promotions";
    stop;
}

# Rule Financial - travel forward [regular expressions]
if 
    header :regex "Subject" "\\b(?i)(flight|confirmation|you're going to).*\\b(reservation|on)\\b"
{
    addflag "\\Seen";
    fileinto "INBOX.Financial.Travel"
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

if 
    address :regex "From" "^(?i:Disneyplus.*$|Netflix.*$|^.*hulu.*$|HBOmax.*$|MoviesAnywhere.*$|iTunes.*$|7digital.*$|Bandcamp.*$|Roku.*$|Plex.*$|Peacock.*$)"
{
    set "read" "Y";
    addflag "\\Seen";
    
    fileinto "INBOX.Financial.Media";
    stop;
}

# Rule Financial - taxes [regular expressions]
