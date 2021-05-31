package org.keycloak.testsuite.rar;

import java.util.List;

public class AccountInformation {

    public enum Action {account, balances, transactions}

    private String type;
    private String iban;
    private List<Action> actions;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getIban() {
        return iban;
    }

    public void setIban(String iban) {
        this.iban = iban;
    }

    public List<Action> getActions() {
        return actions;
    }

    public void setActions(List<Action> actions) {
        this.actions = actions;
    }
}
