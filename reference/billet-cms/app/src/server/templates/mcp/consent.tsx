import { AuthPage } from "../../components/auth-page";
import { CsrfField } from "../../components/csrf-field";
import { Flash } from "../../components/flash";
import { SITE_NAME } from "../../services/seo";

/** The path the consent form posts to; also the CSRF token's binding. */
export const CONSENT_PATH = "/mcp/authorize";

export interface ConsentProps {
  clientName: string;
  /** The connection label the client registered, shown apart from the app name. */
  connectionLabel?: string | null;
  /** The host the authorization code will be sent to, shown to the person. */
  redirectHost: string;
  identityEmail: string;
  requestId: string;
  csrfToken: string | null;
}

/**
 * The one screen where a person grants an AI client authority over the site.
 *
 * It is deliberately plain: who is asking, who they will act as, where they
 * will return, and the single permission this CMS issues. No client name or
 * host is trusted for layout — both are rendered as text, so a registered name
 * cannot inject markup into the page that asks for consent.
 */
export const Consent = ({
  clientName,
  connectionLabel,
  redirectHost,
  identityEmail,
  requestId,
  csrfToken,
}: ConsentProps) => (
  <AuthPage
    title={`Connect an app - ${SITE_NAME}`}
    description="Review an app's request to edit this site's content."
    canonicalPath={CONSENT_PATH}
    heading={`Connect ${clientName}?`}
    subtitle={`It will act as you in ${SITE_NAME}.`}
    footer={null}
  >
    <ul className="consent-details">
      {connectionLabel && (
        <li>
          Connection: <strong>{connectionLabel}</strong>
        </li>
      )}
      <li>
        It can read and change <strong>all content on this site</strong>,
        including publishing and deleting.
      </li>
      <li>
        You are signed in as <strong>{identityEmail}</strong>.
      </li>
      <li>
        After you decide, you will return to <strong>{redirectHost}</strong>.
      </li>
      {/^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i.test(redirectHost) && (
        <li>
          This app will return to a program on this computer. Only continue if
          you started it.
        </li>
      )}
    </ul>

    {!csrfToken ? (
      <Flash
        tone="error"
        title="We couldn't prepare this request in your browser. Check that cookies are enabled and try connecting again."
      />
    ) : (
      <form method="POST" action={CONSENT_PATH} className="consent-actions">
        <CsrfField token={csrfToken} />
        <input type="hidden" name="request" value={requestId} />
        <button
          type="submit"
          name="decision"
          value="approve"
          className="btn btn-primary"
        >
          Allow access
        </button>
        <button
          type="submit"
          name="decision"
          value="deny"
          className="btn btn-ghost"
        >
          Deny
        </button>
      </form>
    )}
  </AuthPage>
);
