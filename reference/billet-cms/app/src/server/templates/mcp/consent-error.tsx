import { AuthPage } from "../../components/auth-page";
import { SITE_NAME } from "../../services/seo";

export interface ConsentErrorProps {
  heading: string;
  message: string;
  siteUrl: string | null;
}

/**
 * A dead end in the OAuth flow, rendered instead of redirecting.
 *
 * An unknown client or an unregistered redirect URI must never be sent
 * anywhere: the redirect is the attack surface. A person who reached this page
 * from a client is told to go back there and try again.
 */
export const ConsentError = ({
  heading,
  message,
  siteUrl,
}: ConsentErrorProps) => (
  <AuthPage
    title={`${heading} - ${SITE_NAME}`}
    description={message}
    canonicalPath="/mcp/authorize"
    heading={heading}
    subtitle={message}
    footer={siteUrl ? <a href={siteUrl}>Back to the site</a> : null}
  />
);
