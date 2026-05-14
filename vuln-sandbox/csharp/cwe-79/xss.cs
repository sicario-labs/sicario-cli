// CWE-79: Cross-Site Scripting — TRUE POSITIVE
// Rule: csharp/xss-html-raw
// Html.Raw() used with user-controlled model data bypasses auto-encoding.

@model UserViewModel

<div>
    @* VULNERABLE: Html.Raw bypasses Razor's automatic HTML encoding *@
    @Html.Raw(Model.UserInput)
</div>
