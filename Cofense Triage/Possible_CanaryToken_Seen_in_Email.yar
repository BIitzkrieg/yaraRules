
rule Possible_CanaryToken_Seen_in_Email
{
  meta:
    description = "This YARA rule looks for possible canary tokens present within emails and attachments. This is generally uncommon, and typically leveraged by defenders to identify anomalous behaviors triggered by attackers, but it has been reported that threat actors are leveraging these now to determine when users open phishing attachments. Condensed ruleset based on references below."
    author = "@singe, modified individual rules into one large rule."
    references = "https://github.com/C0axx/CanaryHunter and https://gist.github.com/singe/0c334b514a9eed2792b88df1dfb766cc"
  strings: 
    $domain = /https??:\/\/canarytokens.com\//
    $remoteimagefield1 = /INCLUDEPICTURE +?"https??:\/\/.{1,200}?" +?\\d/
    $remoteimagefield2 = /INCLUDEPICTURE +?\\d +?"https??:\/\/.{1,200}?"/
    $remoteimagerels = /<Relationship [^>]*?Type="[^"]*?\/image"[^>]*?Target="https??:\/\/[^"]*?"/
  condition:
    any of them
}
