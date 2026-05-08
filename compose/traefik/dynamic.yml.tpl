http:
  middlewares:
    security-headers:
      headers:
        browserXssFilter: true
        contentTypeNosniff: true
        frameDeny: true
        referrerPolicy: no-referrer

    edge-rate-limit:
      rateLimit:
        average: 100
        burst: 50
        period: 1s

    edge-gate:
      forwardAuth:
        address: http://dashboard:3000/api/edge-gate/verify
        trustForwardHeader: true

    crowdsec-bouncer:
      plugin:
        bouncer:
          enabled: true
          logLevel: INFO
          crowdsecMode: live
          crowdsecLapiScheme: http
          crowdsecLapiHost: crowdsec:8080
          crowdsecLapiKey: __CROWDSEC_BOUNCER_API_KEY__
          crowdsecAppsecEnabled: true
          crowdsecAppsecHost: crowdsec:7422
          crowdsecAppsecFailureBlock: false
          crowdsecAppsecUnreachableBlock: false
          forwardedHeadersTrustedIPs:
            - 127.0.0.1/32
            - 172.16.0.0/12
            - 192.168.0.0/16
            - 10.0.0.0/8
