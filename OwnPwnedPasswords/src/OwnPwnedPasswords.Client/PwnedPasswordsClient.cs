using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OwnPwnedPasswords.Client;

/// <inheritdoc />
public class PwnedPasswordsClient : IPwnedPasswordsClient
{
    /// <summary>
    /// The default name used to register the typed HttpClient with the <see cref="IServiceCollection"/>
    /// </summary>
    public const string DefaultName = "PwnedPasswordsClient";

    private readonly HttpClient? _client;
    private readonly ILogger<PwnedPasswordsClient> _logger;
    private readonly PwnedPasswordsClientOptions _options;

    /// <summary>
    /// Create a new instance of <see cref="PwnedPasswordsClient"/>
    /// </summary>
    public PwnedPasswordsClient(HttpClient? client, ILogger<PwnedPasswordsClient> logger, IOptions<PwnedPasswordsClientOptions> options)
    {
        _client = client;
        _logger = logger;
        _options = options.Value;
    }

    /// <inheritdoc />
    public async Task<bool> HasPasswordBeenPwned(string? password, CancellationToken cancellationToken = default)
    {
        var sha1Password = ShaUtil.Sha1HashStringForUtf8String(password);
        var sha1Prefix = sha1Password[..5];
        var sha1Suffix = sha1Password[5..];
        try
        {
            var response = await _client?.GetAsync("range/" + sha1Prefix, cancellationToken)!;

            if (response.IsSuccessStatusCode)
            {
                // Response was a success. Check to see if the SHA1 suffix is in the response body.
                var frequency = await Contains(response.Content, sha1Suffix);
                var isPwned = (frequency >= _options.MinimumFrequencyToConsiderPwned);
                _logger.LogDebug(isPwned
                    ? "HaveIBeenPwned API indicates the password has been pwned"
                    : "HaveIBeenPwned API indicates the password has not been pwned");
                return isPwned;
            }
            _logger.LogWarning("Unexpected response from API: {StatusCode}", response.StatusCode);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error calling Pwned Password API. Assuming password is not pwned");
        }
        return false;
    }

    internal static async Task<long> Contains(HttpContent content, string sha1Suffix)
    {
        using var streamReader = new StreamReader(await content.ReadAsStreamAsync());
        while (!streamReader.EndOfStream)
        {
            var line = await streamReader.ReadLineAsync();
            var segments = line?.Split(':');
            if (segments is { Length: 2 } &&
                string.Equals(segments[0], sha1Suffix, StringComparison.OrdinalIgnoreCase) &&
                long.TryParse(segments[1], out var count))
            {
                return count;
            }
        }

        return 0;

    }
}