// CWE-79: Cross-Site Scripting — TRUE NEGATIVE
// Rule: csharp/xss-html-raw
// Default Razor @expression syntax auto-encodes HTML — safe.

@model UserViewModel

<div>
    @* SAFE: default Razor expression auto-encodes HTML entities *@
    @Model.UserInput
</div>
