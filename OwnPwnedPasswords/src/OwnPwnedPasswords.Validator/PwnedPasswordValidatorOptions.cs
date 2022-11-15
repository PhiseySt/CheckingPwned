﻿namespace OwnPwnedPasswords.Validator;

/// <summary>
/// Options for configuring the <see cref="PwnedPasswordValidator{TUser}"/>
/// </summary>
public class PwnedPasswordValidatorOptions
{
    /// <summary>
    /// The error message to display when a breached password is used.
    /// </summary>
    public string ErrorMessage { get; set; } = "The password you chose has appeared in a data breach.";
}