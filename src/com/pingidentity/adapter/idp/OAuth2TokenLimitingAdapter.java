/***************************************************************************
 * Copyright (C) 2012 Ping Identity Corporation
 * All rights reserved.
 *
 * The contents of this file are subject to the terms of the 
 * Ping Identity Corporation SDK Developer Guide.
 *
 **************************************************************************/

package com.pingidentity.adapter.idp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.axis.utils.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.oauth20.token.AccessGrant;
import org.sourceid.oauth20.token.AccessGrantManager;
import org.sourceid.saml20.adapter.AuthnAdapterException;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor;
import org.sourceid.saml20.adapter.gui.SelectFieldDescriptor;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.impl.IntegerValidator;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;
import org.sourceid.saml20.adapter.idp.authn.AuthnPolicy;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthenticationAdapter;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthnAdapterDescriptor;
import org.sourceid.saml20.domain.mgmt.MgmtFactory;

import com.pingidentity.sdk.AuthnAdapterResponse;
import com.pingidentity.sdk.AuthnAdapterResponse.AUTHN_STATUS;
import com.pingidentity.sdk.IdpAuthenticationAdapterV2;
import com.pingidentity.sdk.template.TemplateRendererUtil;

/**
 * <p>
 * This class will revoke all access tokens for a user which exceed
 * the allowed amount on authentication. It is to be used in conjunction
 * with other adapters, as part of the composite adapter flow.
 * </p>
 * <p>
 */
public class OAuth2TokenLimitingAdapter implements IdpAuthenticationAdapterV2 {

	private static final String RETURNATTR_USERKEY = "userkey";
	private static final String HTML_REVOKE_OPTION = "HTML_REVOKE_OPTION";
	private static final String TEMPLATE_ERROR = "html.oauth2tokenlimiter.error.html";
	
	private final Log log = LogFactory.getLog(this.getClass());
	
	private final Comparator<AccessGrant> ACCESS_TOKEN_COMPARE_EXPIRY = new Comparator<AccessGrant>() {
		public int compare(AccessGrant grant1, AccessGrant grant2) {
			
			if(revokeMethod.equals(OAUTH2_REVOKE_LIFO))
			{
				if(grant1.getIssued() > grant2.getIssued())
					return 1;
				else if(grant1.getIssued() < grant2.getIssued())
					return -1;
				else
					return 0;
			}
			else
			{
				if(grant1.getIssued() < grant2.getIssued())
					return 1;
				else if(grant1.getIssued() > grant2.getIssued())
					return -1;
				else
					return 0;
			}
		}
	};

	private static final String CONFIG_OAUTH2_CLIENTID = "OAuth2 Client ID";
	private static final String CONFIG_OAUTH2_MAXTOKENS = "OAuth2 Maximum Tokens";
	private static final String CONFIG_OAUTH2_SESSIONREVOKEMETHOD = "Session Revocation Method";
	private static final int OAUTH2_MAXTOKENS = 1000;
	private static final String OAUTH2_REVOKE_USERSELECT = "User-Select";
	private static final String OAUTH2_REVOKE_FIFO = "FIFO";
	private static final String OAUTH2_REVOKE_LIFO = "LIFO";
    private static final String[] tokenRevokeMethod = new String[] { OAUTH2_REVOKE_USERSELECT, OAUTH2_REVOKE_FIFO, OAUTH2_REVOKE_LIFO};
    private static final String DEFAULT_REVOKE_METHOD = tokenRevokeMethod[0];

	private final IdpAuthnAdapterDescriptor descriptor;
	private final AccessGrantManager accessGrantMgr;

	private Set<String> oauth2ClientId = new HashSet<String>();
	private int maxTokens = OAUTH2_MAXTOKENS;
	private String revokeMethod = DEFAULT_REVOKE_METHOD;

	/**
	 * Constructor for the Sample Subnet Adapter. Initializes the authentication
	 * adapter descriptor so PingFederate can generate the proper configuration
	 * GUI
	 */
	public OAuth2TokenLimitingAdapter() {
		accessGrantMgr = MgmtFactory.getAccessGrantManager();

		RequiredFieldValidator requiredFieldValidator = new RequiredFieldValidator();
		IntegerValidator integerValidator = new IntegerValidator(1,
				OAUTH2_MAXTOKENS);

		TextFieldDescriptor oauth2ClientIDField = new TextFieldDescriptor(
				CONFIG_OAUTH2_CLIENTID,
				"Enter the clientID(s) of the OAuth client configured in PingFederate. Multiple clientID's separated by comma." +
				" No value indicates that all OAuth client's are subject to this user token limiting adapter.");

		TextFieldDescriptor maxTokensField = new TextFieldDescriptor(
				CONFIG_OAUTH2_MAXTOKENS,
				"Enter the maximum number of tokens a person can have. Please enter in a number 1 - "
						+ OAUTH2_MAXTOKENS + ".");
		maxTokensField.addValidator(integerValidator);
		maxTokensField.addValidator(requiredFieldValidator);

        SelectFieldDescriptor revokeMethodDescriptor = new SelectFieldDescriptor(CONFIG_OAUTH2_SESSIONREVOKEMETHOD, 
        		"Allow users to select which grant they'd like to revoke.", tokenRevokeMethod);
        revokeMethodDescriptor.addValidator(requiredFieldValidator);
        revokeMethodDescriptor.setDefaultValue(DEFAULT_REVOKE_METHOD);

		// Create a GUI descriptor
		AdapterConfigurationGuiDescriptor guiDescriptor = new AdapterConfigurationGuiDescriptor(
				"Set the details of the OAuth2 clients");
		guiDescriptor.addField(oauth2ClientIDField);
		guiDescriptor.addField(maxTokensField);
        guiDescriptor.addField(revokeMethodDescriptor);

		// Create the Idp authentication adapter descriptor
		Set<String> contract = new HashSet<String>();
		contract.add(RETURNATTR_USERKEY);
		descriptor = new IdpAuthnAdapterDescriptor(this,
				"OAuth2 Client Limiting Adapter", contract, false,
				guiDescriptor, false);
	}

	/**
	 *  
	 * @return an IdpAuthnAdapterDescriptor object that describes this IdP
	 *         adapter implementation.
	 */
	public IdpAuthnAdapterDescriptor getAdapterDescriptor() {
		return descriptor;
	}

	/**
	 * 
	 * Logout call - does nothing and always returns true.
	 * 
	 * @param authnIdentifiers
	 *            the map of authentication identifiers originally returned to
	 *            the PingFederate server by the {@link #lookupAuthN} method.
	 *            This enables the adapter to associate a security context or
	 *            session returned by lookupAuthN with the invocation of this
	 *            logout method.
	 * @param req
	 *            the HttpServletRequest can be used to read cookies,
	 *            parameters, headers, etc. It can also be used to find out more
	 *            about the request like the full URL the request was made to.
	 * @param resp
	 *            the HttpServletResponse. The response can be used to
	 *            facilitate an asynchronous interaction. Sending a client side
	 *            redirect or writing (and flushing) custom content to the
	 *            response are two ways that an invocation of this method allows
	 *            for the adapter to take control of the user agent. Note that
	 *            if control of the user agent is taken in this way, then the
	 *            agent must eventually be returned to the
	 *            <code>resumePath</code> endpoint at the PingFederate server to
	 *            complete the protocol transaction.
	 * @param resumePath
	 *            the relative URL that the user agent needs to return to, if
	 *            the implementation of this method invocation needs to operate
	 *            asynchronously. If this method operates synchronously, this
	 *            parameter can be ignored. The resumePath is the full path
	 *            portion of the URL - everything after hostname and port. If
	 *            the hostname, port, or protocol are needed, they can be
	 *            derived using the HttpServletRequest.
	 * @return a boolean indicating if the logout was successful.
	 * @throws AuthnAdapterException
	 *             for any unexpected runtime problem that the implementation
	 *             cannot handle.
	 * @throws IOException
	 *             for any problem with I/O (typically any operation that writes
	 *             to the HttpServletResponse will throw an IOException.
	 * 
	 * @see IdpAuthenticationAdapter#logoutAuthN(Map, HttpServletRequest,
	 *      HttpServletResponse, String)
	 */
	@SuppressWarnings("rawtypes")
	public boolean logoutAuthN(Map authnIdentifiers, HttpServletRequest req,
			HttpServletResponse resp, String resumePath)
			throws AuthnAdapterException, IOException {
		return true;
	}

	/**
	 * This method is called by the PingFederate server to push configuration
	 * values entered by the administrator via the dynamically rendered GUI
	 * configuration screen in the PingFederate administration console. Your
	 * implementation should use the {@link Configuration} parameter to
	 * configure its own internal state as needed. The tables and fields
	 * available in the Configuration object will correspond to the tables and
	 * fields defined on the
	 * {@link org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor}
	 * on the AuthnAdapterDescriptor returned by the
	 * {@link #getAdapterDescriptor()} method of this class. <br/>
	 * <br/>
	 * Each time the PingFederate server creates a new instance of your adapter
	 * implementation this method will be invoked with the proper configuration.
	 * All concurrency issues are handled in the server so you don't need to
	 * worry about them here. The server doesn't allow access to your adapter
	 * implementation instance until after creation and configuration is
	 * completed.
	 * 
	 * @param configuration
	 *            the Configuration object constructed from the values entered
	 *            by the user via the GUI.
	 */
	public void configure(Configuration configuration) {
		String[] oauth2ClientIdSplit = configuration.getFieldValue(
				CONFIG_OAUTH2_CLIENTID).split(",");
		for (String oauth2ClientIdStr : oauth2ClientIdSplit) {
			oauth2ClientId.add(oauth2ClientIdStr.trim());
		}
		maxTokens = configuration.getIntFieldValue(CONFIG_OAUTH2_MAXTOKENS);
		revokeMethod = configuration.getFieldValue(CONFIG_OAUTH2_SESSIONREVOKEMETHOD);
		
	}

	/**
	 * This method is used to retrieve information about the adapter (e.g.
	 * AuthnContext).
	 * <p>
	 * In this example the method not used, return null
	 * </p>
	 * 
	 * @return a map
	 */
	public Map<String, Object> getAdapterInfo() {
		return null;
	}

	/**
	 * Revokes the oldest OAuth client tokens and retains the number of allowed access tokens
	 * as configured by this adapter.
	 * 
	 * @param req
	 *            the HttpServletRequest can be used to read cookies,
	 *            parameters, headers, etc. It can also be used to find out more
	 *            about the request like the full URL the request was made to.
	 *            Accessing the HttpSession from the request is not recommended
	 *            and doing so is deprecated. Use
	 *            {@link org.sourceid.saml20.adapter.state.SessionStateSupport}
	 *            as an alternative.
	 * @param resp
	 *            the HttpServletResponse. The response can be used to
	 *            facilitate an asynchronous interaction. Sending a client side
	 *            redirect or writing (and flushing) custom content to the
	 *            response are two ways that an invocation of this method allows
	 *            for the adapter to take control of the user agent. Note that
	 *            if control of the user agent is taken in this way, then the
	 *            agent must eventually be returned to the
	 *            <code>resumePath</code> endpoint at the PingFederate server to
	 *            complete the protocol transaction.
	 * @param inParameters
	 *            A map that contains a set of input parameters. The input
	 *            parameters provided are detailed in
	 *            {@link IdpAuthenticationAdapterV2}, prefixed with
	 *            <code>IN_PARAMETER_NAME_*</code> i.e.
	 *            {@link IdpAuthenticationAdapterV2#IN_PARAMETER_NAME_RESUME_PATH}
	 *            .
	 * @return {@link AuthnAdapterResponse} The return value should not be null.
	 * @throws AuthnAdapterException
	 *             for any unexpected runtime problem that the implementation
	 *             cannot handle.
	 * @throws IOException
	 *             for any problem with I/O (typically any operation that writes
	 *             to the HttpServletResponse).
	 */
	public AuthnAdapterResponse lookupAuthN(HttpServletRequest req,
			HttpServletResponse resp, Map<String, Object> inParameters)
			throws AuthnAdapterException, IOException {

		String username = inParameters
				.get(IN_PARAMETER_NAME_USERID).toString();
		String resumePath = inParameters
				.get(IN_PARAMETER_NAME_RESUME_PATH).toString();
		
		if(log.isDebugEnabled())
		{
			log.debug("Username: " + username);
		}

		AuthnAdapterResponse authnAdapterResponse = new AuthnAdapterResponse();

		HashMap<String, Object> attributes = new HashMap<String, Object>();

		if (!StringUtils.isEmpty(username)) {

			//gets all of the access tokens after the configured amount,
			//then calls the revoke function
			List<AccessGrant> grants = getAccessGrantByUserKeyClient(username);
			
			if(log.isDebugEnabled())
			{
				log.debug("Number of grants for person: " + grants.size());
			}
			
			if(revokeMethod.equals(OAUTH2_REVOKE_USERSELECT))
			{
				//If grant size exceeds configured amount
				if(grants.size() > (maxTokens-1) )
				{
				    Map<String, Object> params = new HashMap<String, Object>();
				    params.put("action", resumePath);
				    
				    //Retrieve selection list of selected sessions to revoke
					if(req.getParameterValues(HTML_REVOKE_OPTION) != null)
					{
						//revoke each session selected by the user
						String [] revokeUIDs = req.getParameterValues(HTML_REVOKE_OPTION);
						int countRevokes = 0;
						for(String grantUID : revokeUIDs)
						{			
							//reading access grant again as we can't trust what's in the request
							//parameters. The person may press refresh to replay the previous request.
							AccessGrant grant = accessGrantMgr.getByGuid(grantUID);
							if(grant == null)
								continue;
							
							if(log.isDebugEnabled())
							{
								log.debug("Grant being revoked: " + grantUID);
							}
							
							countRevokes++;
							accessGrantMgr.revokeGrant(grantUID);
						}
										
						//check if the user still hasn't selected enough sessions
						//to revoke to get it under the limit
						if((grants.size() - countRevokes) > (maxTokens-1))
						{
							//refresh grant list
							grants = getAccessGrantByUserKeyClient(username);
							int requestRemoveSize = (grants.size() - revokeUIDs.length) - (maxTokens-1);
							params.put("requestRemoveSize", requestRemoveSize);
						    params.put("grants", grants);
							//Request user selection for session revocation
							TemplateRendererUtil.render(req, resp, TEMPLATE_ERROR, params);
						}
						else
						{
							attributes.put(RETURNATTR_USERKEY, username);
				
							authnAdapterResponse.setAuthnStatus(AUTHN_STATUS.SUCCESS);
						}
					}
					else
					{
						int requestRemoveSize = grants.size() - (maxTokens-1);
						params.put("requestRemoveSize", requestRemoveSize);
					    params.put("grants", grants);
						
						//Request user selection for session revocation
						//User has not yet selected which session(s) to revoke
						TemplateRendererUtil.render(req, resp, TEMPLATE_ERROR, params);
					}
				}
				else {
					attributes.put(RETURNATTR_USERKEY, username);
		
					authnAdapterResponse.setAuthnStatus(AUTHN_STATUS.SUCCESS);
				}
			}
			else
			{
				for (int count = (maxTokens-1); count < grants.size(); count++) {
					
					String grantUID = grants.get(count).getGuid();
					
					if(log.isDebugEnabled())
					{
						log.debug("Grant being revoked: " + grantUID);
					}
					
					accessGrantMgr.revokeGrant(grantUID);
				}
	
				attributes.put(RETURNATTR_USERKEY, username);
	
				authnAdapterResponse.setAuthnStatus(AUTHN_STATUS.SUCCESS);
			}
		} else {
			log.error("Unable to determine the userkey value through the chain");
			authnAdapterResponse.setAuthnStatus(AUTHN_STATUS.FAILURE);
		}

		authnAdapterResponse.setAttributeMap(attributes);

		return authnAdapterResponse;
	}

	/**
	 * This method is deprecated. It is not called when
	 * IdpAuthenticationAdapterV2 is implemented. It is replaced by
	 * {@link #lookupAuthN(HttpServletRequest, HttpServletResponse, Map)}
	 * 
	 * @deprecated
	 */
	@SuppressWarnings(value = { "rawtypes" })
	public Map lookupAuthN(HttpServletRequest req, HttpServletResponse resp,
			String partnerSpEntityId, AuthnPolicy authnPolicy, String resumePath)
			throws AuthnAdapterException, IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * Gets a list of access grants for the user in descending order of expiry date
	 * 
	 * @param userKey
	 * @return a list of access grants for the user in descending order of expiry date
	 */
	private List<AccessGrant> getAccessGrantByUserKeyClient(String userKey) {
		Collection<AccessGrant> grants = accessGrantMgr.getByUserKey(userKey);
		List<AccessGrant> userClients = new ArrayList<AccessGrant>();

		for (AccessGrant grant : grants) {
			if (oauth2ClientId.size() == 0
					|| oauth2ClientId.contains(grant.getClientId())) {
				userClients.add(grant);
			}
		}

		Collections.sort(userClients, ACCESS_TOKEN_COMPARE_EXPIRY);

		return userClients;

	}
}
