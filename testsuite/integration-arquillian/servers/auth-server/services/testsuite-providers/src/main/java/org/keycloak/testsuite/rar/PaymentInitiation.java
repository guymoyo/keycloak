package org.keycloak.testsuite.rar;

public class PaymentInitiation {

    private String type;
    private String instructedAmount;
    private String currency;
    private String creditorName;
    private String creditorAccount;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getInstructedAmount() {
        return instructedAmount;
    }

    public void setInstructedAmount(String instructedAmount) {
        this.instructedAmount = instructedAmount;
    }

    public String getCurrency() {
        return currency;
    }

    public void setCurrency(String currency) {
        this.currency = currency;
    }

    public String getCreditorName() {
        return creditorName;
    }

    public void setCreditorName(String creditorName) {
        this.creditorName = creditorName;
    }

    public String getCreditorAccount() {
        return creditorAccount;
    }

    public void setCreditorAccount(String creditorAccount) {
        this.creditorAccount = creditorAccount;
    }
}
