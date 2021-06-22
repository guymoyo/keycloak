<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        ${msg("grantRequiredTitle")}
    <#elseif section = "form">

        <div class="${properties.kcFormGroupClass!}">
            <div class="${properties.kcLabelWrapperClass!}">
                <label for="creditorAccount" class="${properties.kcLabelClass!}">Creditor Account</label>
                <span>${authorizationDetails.creditorAccount}</span>
            </div>
            <div class="${properties.kcLabelWrapperClass!}">
                <label for="instructedAmount" class="${properties.kcLabelClass!}">Amount</label>
                <span>${authorizationDetails.instructedAmount}</span>
            </div>
            <div class="${properties.kcLabelWrapperClass!}">
                <label for="debitorAccount" class="${properties.kcLabelClass!}">Debitor Account</label>
                <span>${authorizationDetails.debitorAccount}</span>
            </div>
        </div>
        <form class="form-actions" action="${url.loginAction}" method="POST">
            <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}" name="accept" id="kc-accept" type="submit" value="${msg("doYes")}"/>
            <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}" name="cancel" id="kc-decline" type="submit" value="${msg("doNo")}"/>
        </form>
        <div class="clearfix"></div>
    </#if>
</@layout.registrationLayout>