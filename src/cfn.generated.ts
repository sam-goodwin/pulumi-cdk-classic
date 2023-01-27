export interface Tag {
  Key: string;
  Value: string;
}
export namespace ACMPCA {
  export interface Certificate {
    ApiPassthrough?: Certificate.ApiPassthrough;
    CertificateAuthorityArn: string;
    CertificateSigningRequest: string;
    SigningAlgorithm: string;
    TemplateArn?: string;
    Validity: Certificate.Validity;
    ValidityNotBefore?: Certificate.Validity;
  }
  export namespace Certificate {
    export interface Attr {
      Arn: string;
      Certificate: string;
    }
    export interface ApiPassthrough {
      Extensions?: Extensions;
      Subject?: Subject;
    }
    export interface CustomAttribute {
      ObjectIdentifier: string;
      Value: string;
    }
    export interface CustomExtension {
      Critical?: boolean;
      ObjectIdentifier: string;
      Value: string;
    }
    export interface EdiPartyName {
      NameAssigner: string;
      PartyName: string;
    }
    export interface ExtendedKeyUsage {
      ExtendedKeyUsageObjectIdentifier?: string;
      ExtendedKeyUsageType?: string;
    }
    export interface Extensions {
      CertificatePolicies?: PolicyInformation[];
      CustomExtensions?: CustomExtension[];
      ExtendedKeyUsage?: ExtendedKeyUsage[];
      KeyUsage?: KeyUsage;
      SubjectAlternativeNames?: GeneralName[];
    }
    export interface GeneralName {
      DirectoryName?: Subject;
      DnsName?: string;
      EdiPartyName?: EdiPartyName;
      IpAddress?: string;
      OtherName?: OtherName;
      RegisteredId?: string;
      Rfc822Name?: string;
      UniformResourceIdentifier?: string;
    }
    export interface KeyUsage {
      CRLSign?: boolean;
      DataEncipherment?: boolean;
      DecipherOnly?: boolean;
      DigitalSignature?: boolean;
      EncipherOnly?: boolean;
      KeyAgreement?: boolean;
      KeyCertSign?: boolean;
      KeyEncipherment?: boolean;
      NonRepudiation?: boolean;
    }
    export interface OtherName {
      TypeId: string;
      Value: string;
    }
    export interface PolicyInformation {
      CertPolicyId: string;
      PolicyQualifiers?: PolicyQualifierInfo[];
    }
    export interface PolicyQualifierInfo {
      PolicyQualifierId: string;
      Qualifier: Qualifier;
    }
    export interface Qualifier {
      CpsUri: string;
    }
    export interface Subject {
      CommonName?: string;
      Country?: string;
      CustomAttributes?: CustomAttribute[];
      DistinguishedNameQualifier?: string;
      GenerationQualifier?: string;
      GivenName?: string;
      Initials?: string;
      Locality?: string;
      Organization?: string;
      OrganizationalUnit?: string;
      Pseudonym?: string;
      SerialNumber?: string;
      State?: string;
      Surname?: string;
      Title?: string;
    }
    export interface Validity {
      Type: string;
      Value: number;
    }
  }
  export interface CertificateAuthority {
    CsrExtensions?: CertificateAuthority.CsrExtensions;
    KeyAlgorithm: string;
    KeyStorageSecurityStandard?: string;
    RevocationConfiguration?: CertificateAuthority.RevocationConfiguration;
    SigningAlgorithm: string;
    Subject: CertificateAuthority.Subject;
    Tags?: Tag[];
    Type: string;
    UsageMode?: string;
  }
  export namespace CertificateAuthority {
    export interface Attr {
      Arn: string;
      CertificateSigningRequest: string;
    }
    export interface AccessDescription {
      AccessLocation: GeneralName;
      AccessMethod: AccessMethod;
    }
    export interface AccessMethod {
      AccessMethodType?: string;
      CustomObjectIdentifier?: string;
    }
    export interface CrlConfiguration {
      CustomCname?: string;
      Enabled?: boolean;
      ExpirationInDays?: number;
      S3BucketName?: string;
      S3ObjectAcl?: string;
    }
    export interface CsrExtensions {
      KeyUsage?: KeyUsage;
      SubjectInformationAccess?: AccessDescription[];
    }
    export interface CustomAttribute {
      ObjectIdentifier: string;
      Value: string;
    }
    export interface EdiPartyName {
      NameAssigner: string;
      PartyName: string;
    }
    export interface GeneralName {
      DirectoryName?: Subject;
      DnsName?: string;
      EdiPartyName?: EdiPartyName;
      IpAddress?: string;
      OtherName?: OtherName;
      RegisteredId?: string;
      Rfc822Name?: string;
      UniformResourceIdentifier?: string;
    }
    export interface KeyUsage {
      CRLSign?: boolean;
      DataEncipherment?: boolean;
      DecipherOnly?: boolean;
      DigitalSignature?: boolean;
      EncipherOnly?: boolean;
      KeyAgreement?: boolean;
      KeyCertSign?: boolean;
      KeyEncipherment?: boolean;
      NonRepudiation?: boolean;
    }
    export interface OcspConfiguration {
      Enabled?: boolean;
      OcspCustomCname?: string;
    }
    export interface OtherName {
      TypeId: string;
      Value: string;
    }
    export interface RevocationConfiguration {
      CrlConfiguration?: CrlConfiguration;
      OcspConfiguration?: OcspConfiguration;
    }
    export interface Subject {
      CommonName?: string;
      Country?: string;
      CustomAttributes?: CustomAttribute[];
      DistinguishedNameQualifier?: string;
      GenerationQualifier?: string;
      GivenName?: string;
      Initials?: string;
      Locality?: string;
      Organization?: string;
      OrganizationalUnit?: string;
      Pseudonym?: string;
      SerialNumber?: string;
      State?: string;
      Surname?: string;
      Title?: string;
    }
  }
  export interface CertificateAuthorityActivation {
    Certificate: string;
    CertificateAuthorityArn: string;
    CertificateChain?: string;
    Status?: string;
  }
  export interface Permission {
    Actions: string[];
    CertificateAuthorityArn: string;
    Principal: string;
    SourceAccount?: string;
  }
}
export namespace APS {
  export interface RuleGroupsNamespace {
    Data: string;
    Name: string;
    Tags?: Tag[];
    Workspace: string;
  }
  export interface Workspace {
    AlertManagerDefinition?: string;
    Alias?: string;
    LoggingConfiguration?: Workspace.LoggingConfiguration;
    Tags?: Tag[];
  }
  export namespace Workspace {
    export interface Attr {
      Arn: string;
      PrometheusEndpoint: string;
      WorkspaceId: string;
    }
    export interface LoggingConfiguration {
      LogGroupArn?: string;
    }
  }
}
export namespace AccessAnalyzer {
  export interface Analyzer {
    AnalyzerName?: string;
    ArchiveRules?: Analyzer.ArchiveRule[];
    Tags?: Tag[];
    Type: string;
  }
  export namespace Analyzer {
    export interface Attr {
      Arn: string;
    }
    export interface ArchiveRule {
      Filter: Filter[];
      RuleName: string;
    }
    export interface Filter {
      Contains?: string[];
      Eq?: string[];
      Exists?: boolean;
      Neq?: string[];
      Property: string;
    }
  }
}
export namespace AmazonMQ {
  export interface Broker {
    AuthenticationStrategy?: string;
    AutoMinorVersionUpgrade: boolean;
    BrokerName: string;
    Configuration?: Broker.ConfigurationId;
    DeploymentMode: string;
    EncryptionOptions?: Broker.EncryptionOptions;
    EngineType: string;
    EngineVersion: string;
    HostInstanceType: string;
    LdapServerMetadata?: Broker.LdapServerMetadata;
    Logs?: Broker.LogList;
    MaintenanceWindowStartTime?: Broker.MaintenanceWindow;
    PubliclyAccessible: boolean;
    SecurityGroups?: string[];
    StorageType?: string;
    SubnetIds?: string[];
    Tags?: Broker.TagsEntry[];
    Users: Broker.User[];
  }
  export namespace Broker {
    export interface Attr {
      AmqpEndpoints: string[];
      Arn: string;
      ConfigurationId: string;
      ConfigurationRevision: number;
      IpAddresses: string[];
      MqttEndpoints: string[];
      OpenWireEndpoints: string[];
      StompEndpoints: string[];
      WssEndpoints: string[];
    }
    export interface ConfigurationId {
      Id: string;
      Revision: number;
    }
    export interface EncryptionOptions {
      KmsKeyId?: string;
      UseAwsOwnedKey: boolean;
    }
    export interface LdapServerMetadata {
      Hosts: string[];
      RoleBase: string;
      RoleName?: string;
      RoleSearchMatching: string;
      RoleSearchSubtree?: boolean;
      ServiceAccountPassword: string;
      ServiceAccountUsername: string;
      UserBase: string;
      UserRoleName?: string;
      UserSearchMatching: string;
      UserSearchSubtree?: boolean;
    }
    export interface LogList {
      Audit?: boolean;
      General?: boolean;
    }
    export interface MaintenanceWindow {
      DayOfWeek: string;
      TimeOfDay: string;
      TimeZone: string;
    }
    export interface TagsEntry {
      Key: string;
      Value: string;
    }
    export interface User {
      ConsoleAccess?: boolean;
      Groups?: string[];
      Password: string;
      Username: string;
    }
  }
  export interface Configuration {
    AuthenticationStrategy?: string;
    Data: string;
    Description?: string;
    EngineType: string;
    EngineVersion: string;
    Name: string;
    Tags?: Configuration.TagsEntry[];
  }
  export namespace Configuration {
    export interface Attr {
      Arn: string;
      Id: string;
      Revision: number;
    }
    export interface TagsEntry {
      Key: string;
      Value: string;
    }
  }
  export interface ConfigurationAssociation {
    Broker: string;
    Configuration: ConfigurationAssociation.ConfigurationId;
  }
  export namespace ConfigurationAssociation {
    export interface Attr {}
    export interface ConfigurationId {
      Id: string;
      Revision: number;
    }
  }
}
export namespace Amplify {
  export interface App {
    AccessToken?: string;
    AutoBranchCreationConfig?: App.AutoBranchCreationConfig;
    BasicAuthConfig?: App.BasicAuthConfig;
    BuildSpec?: string;
    CustomHeaders?: string;
    CustomRules?: App.CustomRule[];
    Description?: string;
    EnableBranchAutoDeletion?: boolean;
    EnvironmentVariables?: App.EnvironmentVariable[];
    IAMServiceRole?: string;
    Name: string;
    OauthToken?: string;
    Platform?: string;
    Repository?: string;
    Tags?: Tag[];
  }
  export namespace App {
    export interface Attr {
      AppId: string;
      AppName: string;
      Arn: string;
      DefaultDomain: string;
    }
    export interface AutoBranchCreationConfig {
      AutoBranchCreationPatterns?: string[];
      BasicAuthConfig?: BasicAuthConfig;
      BuildSpec?: string;
      EnableAutoBranchCreation?: boolean;
      EnableAutoBuild?: boolean;
      EnablePerformanceMode?: boolean;
      EnablePullRequestPreview?: boolean;
      EnvironmentVariables?: EnvironmentVariable[];
      Framework?: string;
      PullRequestEnvironmentName?: string;
      Stage?: string;
    }
    export interface BasicAuthConfig {
      EnableBasicAuth?: boolean;
      Password?: string;
      Username?: string;
    }
    export interface CustomRule {
      Condition?: string;
      Source: string;
      Status?: string;
      Target: string;
    }
    export interface EnvironmentVariable {
      Name: string;
      Value: string;
    }
  }
  export interface Branch {
    AppId: string;
    BasicAuthConfig?: Branch.BasicAuthConfig;
    BranchName: string;
    BuildSpec?: string;
    Description?: string;
    EnableAutoBuild?: boolean;
    EnablePerformanceMode?: boolean;
    EnablePullRequestPreview?: boolean;
    EnvironmentVariables?: Branch.EnvironmentVariable[];
    Framework?: string;
    PullRequestEnvironmentName?: string;
    Stage?: string;
    Tags?: Tag[];
  }
  export namespace Branch {
    export interface Attr {
      Arn: string;
      BranchName: string;
    }
    export interface BasicAuthConfig {
      EnableBasicAuth?: boolean;
      Password: string;
      Username: string;
    }
    export interface EnvironmentVariable {
      Name: string;
      Value: string;
    }
  }
  export interface Domain {
    AppId: string;
    AutoSubDomainCreationPatterns?: string[];
    AutoSubDomainIAMRole?: string;
    DomainName: string;
    EnableAutoSubDomain?: boolean;
    SubDomainSettings: Domain.SubDomainSetting[];
  }
  export namespace Domain {
    export interface Attr {
      Arn: string;
      AutoSubDomainCreationPatterns: string[];
      AutoSubDomainIAMRole: string;
      CertificateRecord: string;
      DomainName: string;
      DomainStatus: string;
      EnableAutoSubDomain: boolean;
      StatusReason: string;
    }
    export interface SubDomainSetting {
      BranchName: string;
      Prefix: string;
    }
  }
}
export namespace AmplifyUIBuilder {
  export interface Component {
    BindingProperties: Record<
      string,
      Component.ComponentBindingPropertiesValue
    >;
    Children?: Component.ComponentChild[];
    CollectionProperties?: Record<string, Component.ComponentDataConfiguration>;
    ComponentType: string;
    Events?: Record<string, Component.ComponentEvent>;
    Name: string;
    Overrides: any;
    Properties: Record<string, Component.ComponentProperty>;
    SchemaVersion?: string;
    SourceId?: string;
    Tags?: Record<string, string>;
    Variants: Component.ComponentVariant[];
  }
  export namespace Component {
    export interface Attr {
      AppId: string;
      EnvironmentName: string;
      Id: string;
    }
    export interface ActionParameters {
      Anchor?: ComponentProperty;
      Fields?: Record<string, ComponentProperty>;
      Global?: ComponentProperty;
      Id?: ComponentProperty;
      Model?: string;
      State?: MutationActionSetStateParameter;
      Target?: ComponentProperty;
      Type?: ComponentProperty;
      Url?: ComponentProperty;
    }
    export interface ComponentBindingPropertiesValue {
      BindingProperties?: ComponentBindingPropertiesValueProperties;
      DefaultValue?: string;
      Type?: string;
    }
    export interface ComponentBindingPropertiesValueProperties {
      Bucket?: string;
      DefaultValue?: string;
      Field?: string;
      Key?: string;
      Model?: string;
      Predicates?: Predicate[];
      UserAttribute?: string;
    }
    export interface ComponentChild {
      Children?: ComponentChild[];
      ComponentType: string;
      Events?: Record<string, ComponentEvent>;
      Name: string;
      Properties: Record<string, ComponentProperty>;
    }
    export interface ComponentConditionProperty {
      Else?: ComponentProperty;
      Field?: string;
      Operand?: string;
      OperandType?: string;
      Operator?: string;
      Property?: string;
      Then?: ComponentProperty;
    }
    export interface ComponentDataConfiguration {
      Identifiers?: string[];
      Model: string;
      Predicate?: Predicate;
      Sort?: SortProperty[];
    }
    export interface ComponentEvent {
      Action?: string;
      Parameters?: ActionParameters;
    }
    export interface ComponentProperty {
      BindingProperties?: ComponentPropertyBindingProperties;
      Bindings?: Record<string, FormBindingElement>;
      CollectionBindingProperties?: ComponentPropertyBindingProperties;
      ComponentName?: string;
      Concat?: ComponentProperty[];
      Condition?: ComponentConditionProperty;
      Configured?: boolean;
      DefaultValue?: string;
      Event?: string;
      ImportedValue?: string;
      Model?: string;
      Property?: string;
      Type?: string;
      UserAttribute?: string;
      Value?: string;
    }
    export interface ComponentPropertyBindingProperties {
      Field?: string;
      Property: string;
    }
    export interface ComponentVariant {
      Overrides?: any;
      VariantValues?: Record<string, string>;
    }
    export interface FormBindingElement {
      Element: string;
      Property: string;
    }
    export interface MutationActionSetStateParameter {
      ComponentName: string;
      Property: string;
      Set: ComponentProperty;
    }
    export interface Predicate {
      And?: Predicate[];
      Field?: string;
      Operand?: string;
      Operator?: string;
      Or?: Predicate[];
    }
    export interface SortProperty {
      Direction: string;
      Field: string;
    }
  }
  export interface Form {
    AppId?: string;
    Cta?: Form.FormCTA;
    DataType: Form.FormDataTypeConfig;
    EnvironmentName?: string;
    Fields: Record<string, Form.FieldConfig>;
    FormActionType: string;
    Name: string;
    SchemaVersion: string;
    SectionalElements: Record<string, Form.SectionalElement>;
    Style: Form.FormStyle;
    Tags?: Record<string, string>;
  }
  export namespace Form {
    export interface Attr {
      Id: string;
    }
    export interface FieldConfig {
      Excluded?: boolean;
      InputType?: FieldInputConfig;
      Label?: string;
      Position?: FieldPosition;
      Validations?: FieldValidationConfiguration[];
    }
    export interface FieldInputConfig {
      DefaultChecked?: boolean;
      DefaultCountryCode?: string;
      DefaultValue?: string;
      DescriptiveText?: string;
      MaxValue?: number;
      MinValue?: number;
      Name?: string;
      Placeholder?: string;
      ReadOnly?: boolean;
      Required?: boolean;
      Step?: number;
      Type: string;
      Value?: string;
      ValueMappings?: ValueMappings;
    }
    export interface FieldPosition {
      Below?: string;
      Fixed?: string;
      RightOf?: string;
    }
    export interface FieldValidationConfiguration {
      NumValues?: number[];
      StrValues?: string[];
      Type: string;
      ValidationMessage?: string;
    }
    export interface FormButton {
      Children?: string;
      Excluded?: boolean;
      Position?: FieldPosition;
    }
    export interface FormCTA {
      Cancel?: FormButton;
      Clear?: FormButton;
      Position?: string;
      Submit?: FormButton;
    }
    export interface FormDataTypeConfig {
      DataSourceType: string;
      DataTypeName: string;
    }
    export interface FormInputValueProperty {
      Value?: string;
    }
    export interface FormStyle {
      HorizontalGap?: FormStyleConfig;
      OuterPadding?: FormStyleConfig;
      VerticalGap?: FormStyleConfig;
    }
    export interface FormStyleConfig {
      TokenReference?: string;
      Value?: string;
    }
    export interface SectionalElement {
      Level?: number;
      Orientation?: string;
      Position?: FieldPosition;
      Text?: string;
      Type: string;
    }
    export interface ValueMapping {
      DisplayValue?: FormInputValueProperty;
      Value: FormInputValueProperty;
    }
    export interface ValueMappings {
      Values: ValueMapping[];
    }
  }
  export interface Theme {
    Name: string;
    Overrides?: Theme.ThemeValues[];
    Tags?: Record<string, string>;
    Values: Theme.ThemeValues[];
  }
  export namespace Theme {
    export interface Attr {
      AppId: string;
      CreatedAt: string;
      EnvironmentName: string;
      Id: string;
      ModifiedAt: string;
    }
    export interface ThemeValue {
      Children?: ThemeValues[];
      Value?: string;
    }
    export interface ThemeValues {
      Key?: string;
      Value?: ThemeValue;
    }
  }
}
export namespace ApiGateway {
  export interface Account {
    CloudWatchRoleArn?: string;
  }
  export interface ApiKey {
    CustomerId?: string;
    Description?: string;
    Enabled?: boolean;
    GenerateDistinctId?: boolean;
    Name?: string;
    StageKeys?: ApiKey.StageKey[];
    Tags?: Tag[];
    Value?: string;
  }
  export namespace ApiKey {
    export interface Attr {
      APIKeyId: string;
    }
    export interface StageKey {
      RestApiId?: string;
      StageName?: string;
    }
  }
  export interface Authorizer {
    AuthType?: string;
    AuthorizerCredentials?: string;
    AuthorizerResultTtlInSeconds?: number;
    AuthorizerUri?: string;
    IdentitySource?: string;
    IdentityValidationExpression?: string;
    Name: string;
    ProviderARNs?: string[];
    RestApiId: string;
    Type: string;
  }
  export interface BasePathMapping {
    BasePath?: string;
    DomainName: string;
    Id?: string;
    RestApiId?: string;
    Stage?: string;
  }
  export interface ClientCertificate {
    Description?: string;
    Tags?: Tag[];
  }
  export interface Deployment {
    DeploymentCanarySettings?: Deployment.DeploymentCanarySettings;
    Description?: string;
    RestApiId: string;
    StageDescription?: Deployment.StageDescription;
    StageName?: string;
  }
  export namespace Deployment {
    export interface Attr {
      DeploymentId: string;
    }
    export interface AccessLogSetting {
      DestinationArn?: string;
      Format?: string;
    }
    export interface CanarySetting {
      PercentTraffic?: number;
      StageVariableOverrides?: Record<string, string>;
      UseStageCache?: boolean;
    }
    export interface DeploymentCanarySettings {
      PercentTraffic?: number;
      StageVariableOverrides?: Record<string, string>;
      UseStageCache?: boolean;
    }
    export interface MethodSetting {
      CacheDataEncrypted?: boolean;
      CacheTtlInSeconds?: number;
      CachingEnabled?: boolean;
      DataTraceEnabled?: boolean;
      HttpMethod?: string;
      LoggingLevel?: string;
      MetricsEnabled?: boolean;
      ResourcePath?: string;
      ThrottlingBurstLimit?: number;
      ThrottlingRateLimit?: number;
    }
    export interface StageDescription {
      AccessLogSetting?: AccessLogSetting;
      CacheClusterEnabled?: boolean;
      CacheClusterSize?: string;
      CacheDataEncrypted?: boolean;
      CacheTtlInSeconds?: number;
      CachingEnabled?: boolean;
      CanarySetting?: CanarySetting;
      ClientCertificateId?: string;
      DataTraceEnabled?: boolean;
      Description?: string;
      DocumentationVersion?: string;
      LoggingLevel?: string;
      MethodSettings?: MethodSetting[];
      MetricsEnabled?: boolean;
      Tags?: Tag[];
      ThrottlingBurstLimit?: number;
      ThrottlingRateLimit?: number;
      TracingEnabled?: boolean;
      Variables?: Record<string, string>;
    }
  }
  export interface DocumentationPart {
    Location: DocumentationPart.Location;
    Properties: string;
    RestApiId: string;
  }
  export namespace DocumentationPart {
    export interface Attr {
      DocumentationPartId: string;
    }
    export interface Location {
      Method?: string;
      Name?: string;
      Path?: string;
      StatusCode?: string;
      Type?: string;
    }
  }
  export interface DocumentationVersion {
    Description?: string;
    DocumentationVersion: string;
    RestApiId: string;
  }
  export interface DomainName {
    CertificateArn?: string;
    DomainName?: string;
    EndpointConfiguration?: DomainName.EndpointConfiguration;
    MutualTlsAuthentication?: DomainName.MutualTlsAuthentication;
    OwnershipVerificationCertificateArn?: string;
    RegionalCertificateArn?: string;
    SecurityPolicy?: string;
    Tags?: Tag[];
  }
  export namespace DomainName {
    export interface Attr {
      DistributionDomainName: string;
      DistributionHostedZoneId: string;
      RegionalDomainName: string;
      RegionalHostedZoneId: string;
    }
    export interface EndpointConfiguration {
      Types?: string[];
    }
    export interface MutualTlsAuthentication {
      TruststoreUri?: string;
      TruststoreVersion?: string;
    }
  }
  export interface GatewayResponse {
    ResponseParameters?: Record<string, string>;
    ResponseTemplates?: Record<string, string>;
    ResponseType: string;
    RestApiId: string;
    StatusCode?: string;
  }
  export interface Method {
    ApiKeyRequired?: boolean;
    AuthorizationScopes?: string[];
    AuthorizationType?: string;
    AuthorizerId?: string;
    HttpMethod: string;
    Integration?: Method.Integration;
    MethodResponses?: Method.MethodResponse[];
    OperationName?: string;
    RequestModels?: Record<string, string>;
    RequestParameters?: Record<string, boolean>;
    RequestValidatorId?: string;
    ResourceId: string;
    RestApiId: string;
  }
  export namespace Method {
    export interface Attr {}
    export interface Integration {
      CacheKeyParameters?: string[];
      CacheNamespace?: string;
      ConnectionId?: string;
      ConnectionType?: string;
      ContentHandling?: string;
      Credentials?: string;
      IntegrationHttpMethod?: string;
      IntegrationResponses?: IntegrationResponse[];
      PassthroughBehavior?: string;
      RequestParameters?: Record<string, string>;
      RequestTemplates?: Record<string, string>;
      TimeoutInMillis?: number;
      Type?: string;
      Uri?: string;
    }
    export interface IntegrationResponse {
      ContentHandling?: string;
      ResponseParameters?: Record<string, string>;
      ResponseTemplates?: Record<string, string>;
      SelectionPattern?: string;
      StatusCode: string;
    }
    export interface MethodResponse {
      ResponseModels?: Record<string, string>;
      ResponseParameters?: Record<string, boolean>;
      StatusCode: string;
    }
  }
  export interface Model {
    ContentType?: string;
    Description?: string;
    Name?: string;
    RestApiId: string;
    Schema?: any;
  }
  export interface RequestValidator {
    Name?: string;
    RestApiId: string;
    ValidateRequestBody?: boolean;
    ValidateRequestParameters?: boolean;
  }
  export interface Resource {
    ParentId: string;
    PathPart: string;
    RestApiId: string;
  }
  export interface RestApi {
    ApiKeySourceType?: string;
    BinaryMediaTypes?: string[];
    Body?: any;
    BodyS3Location?: RestApi.S3Location;
    CloneFrom?: string;
    Description?: string;
    DisableExecuteApiEndpoint?: boolean;
    EndpointConfiguration?: RestApi.EndpointConfiguration;
    FailOnWarnings?: boolean;
    MinimumCompressionSize?: number;
    Mode?: string;
    Name?: string;
    Parameters?: Record<string, string>;
    Policy?: any;
    Tags?: Tag[];
  }
  export namespace RestApi {
    export interface Attr {
      RestApiId: string;
      RootResourceId: string;
    }
    export interface EndpointConfiguration {
      Types?: string[];
      VpcEndpointIds?: string[];
    }
    export interface S3Location {
      Bucket?: string;
      ETag?: string;
      Key?: string;
      Version?: string;
    }
  }
  export interface Stage {
    AccessLogSetting?: Stage.AccessLogSetting;
    CacheClusterEnabled?: boolean;
    CacheClusterSize?: string;
    CanarySetting?: Stage.CanarySetting;
    ClientCertificateId?: string;
    DeploymentId?: string;
    Description?: string;
    DocumentationVersion?: string;
    MethodSettings?: Stage.MethodSetting[];
    RestApiId: string;
    StageName?: string;
    Tags?: Tag[];
    TracingEnabled?: boolean;
    Variables?: Record<string, string>;
  }
  export namespace Stage {
    export interface Attr {}
    export interface AccessLogSetting {
      DestinationArn?: string;
      Format?: string;
    }
    export interface CanarySetting {
      DeploymentId?: string;
      PercentTraffic?: number;
      StageVariableOverrides?: Record<string, string>;
      UseStageCache?: boolean;
    }
    export interface MethodSetting {
      CacheDataEncrypted?: boolean;
      CacheTtlInSeconds?: number;
      CachingEnabled?: boolean;
      DataTraceEnabled?: boolean;
      HttpMethod?: string;
      LoggingLevel?: string;
      MetricsEnabled?: boolean;
      ResourcePath?: string;
      ThrottlingBurstLimit?: number;
      ThrottlingRateLimit?: number;
    }
  }
  export interface UsagePlan {
    ApiStages?: UsagePlan.ApiStage[];
    Description?: string;
    Quota?: UsagePlan.QuotaSettings;
    Tags?: Tag[];
    Throttle?: UsagePlan.ThrottleSettings;
    UsagePlanName?: string;
  }
  export namespace UsagePlan {
    export interface Attr {
      Id: string;
    }
    export interface ApiStage {
      ApiId?: string;
      Stage?: string;
      Throttle?: Record<string, ThrottleSettings>;
    }
    export interface QuotaSettings {
      Limit?: number;
      Offset?: number;
      Period?: string;
    }
    export interface ThrottleSettings {
      BurstLimit?: number;
      RateLimit?: number;
    }
  }
  export interface UsagePlanKey {
    KeyId: string;
    KeyType: string;
    UsagePlanId: string;
  }
  export interface VpcLink {
    Description?: string;
    Name: string;
    Tags?: Tag[];
    TargetArns: string[];
  }
}
export namespace ApiGatewayV2 {
  export interface Api {
    ApiKeySelectionExpression?: string;
    BasePath?: string;
    Body?: any;
    BodyS3Location?: Api.BodyS3Location;
    CorsConfiguration?: Api.Cors;
    CredentialsArn?: string;
    Description?: string;
    DisableExecuteApiEndpoint?: boolean;
    DisableSchemaValidation?: boolean;
    FailOnWarnings?: boolean;
    Name?: string;
    ProtocolType?: string;
    RouteKey?: string;
    RouteSelectionExpression?: string;
    Tags?: Record<string, string>;
    Target?: string;
    Version?: string;
  }
  export namespace Api {
    export interface Attr {
      ApiEndpoint: string;
      ApiId: string;
    }
    export interface BodyS3Location {
      Bucket?: string;
      Etag?: string;
      Key?: string;
      Version?: string;
    }
    export interface Cors {
      AllowCredentials?: boolean;
      AllowHeaders?: string[];
      AllowMethods?: string[];
      AllowOrigins?: string[];
      ExposeHeaders?: string[];
      MaxAge?: number;
    }
  }
  export interface ApiGatewayManagedOverrides {
    ApiId: string;
    Integration?: ApiGatewayManagedOverrides.IntegrationOverrides;
    Route?: ApiGatewayManagedOverrides.RouteOverrides;
    Stage?: ApiGatewayManagedOverrides.StageOverrides;
  }
  export namespace ApiGatewayManagedOverrides {
    export interface Attr {}
    export interface AccessLogSettings {
      DestinationArn?: string;
      Format?: string;
    }
    export interface IntegrationOverrides {
      Description?: string;
      IntegrationMethod?: string;
      PayloadFormatVersion?: string;
      TimeoutInMillis?: number;
    }
    export interface RouteOverrides {
      AuthorizationScopes?: string[];
      AuthorizationType?: string;
      AuthorizerId?: string;
      OperationName?: string;
      Target?: string;
    }
    export interface RouteSettings {
      DataTraceEnabled?: boolean;
      DetailedMetricsEnabled?: boolean;
      LoggingLevel?: string;
      ThrottlingBurstLimit?: number;
      ThrottlingRateLimit?: number;
    }
    export interface StageOverrides {
      AccessLogSettings?: AccessLogSettings;
      AutoDeploy?: boolean;
      DefaultRouteSettings?: RouteSettings;
      Description?: string;
      RouteSettings?: any;
      StageVariables?: any;
    }
  }
  export interface ApiMapping {
    ApiId: string;
    ApiMappingKey?: string;
    DomainName: string;
    Stage: string;
  }
  export interface Authorizer {
    ApiId: string;
    AuthorizerCredentialsArn?: string;
    AuthorizerPayloadFormatVersion?: string;
    AuthorizerResultTtlInSeconds?: number;
    AuthorizerType: string;
    AuthorizerUri?: string;
    EnableSimpleResponses?: boolean;
    IdentitySource?: string[];
    IdentityValidationExpression?: string;
    JwtConfiguration?: Authorizer.JWTConfiguration;
    Name: string;
  }
  export namespace Authorizer {
    export interface Attr {
      AuthorizerId: string;
    }
    export interface JWTConfiguration {
      Audience?: string[];
      Issuer?: string;
    }
  }
  export interface Deployment {
    ApiId: string;
    Description?: string;
    StageName?: string;
  }
  export interface DomainName {
    DomainName: string;
    DomainNameConfigurations?: DomainName.DomainNameConfiguration[];
    MutualTlsAuthentication?: DomainName.MutualTlsAuthentication;
    Tags?: any;
  }
  export namespace DomainName {
    export interface Attr {
      RegionalDomainName: string;
      RegionalHostedZoneId: string;
    }
    export interface DomainNameConfiguration {
      CertificateArn?: string;
      CertificateName?: string;
      EndpointType?: string;
      OwnershipVerificationCertificateArn?: string;
      SecurityPolicy?: string;
    }
    export interface MutualTlsAuthentication {
      TruststoreUri?: string;
      TruststoreVersion?: string;
    }
  }
  export interface Integration {
    ApiId: string;
    ConnectionId?: string;
    ConnectionType?: string;
    ContentHandlingStrategy?: string;
    CredentialsArn?: string;
    Description?: string;
    IntegrationMethod?: string;
    IntegrationSubtype?: string;
    IntegrationType: string;
    IntegrationUri?: string;
    PassthroughBehavior?: string;
    PayloadFormatVersion?: string;
    RequestParameters?: any;
    RequestTemplates?: any;
    ResponseParameters?: any;
    TemplateSelectionExpression?: string;
    TimeoutInMillis?: number;
    TlsConfig?: Integration.TlsConfig;
  }
  export namespace Integration {
    export interface Attr {}
    export interface ResponseParameter {
      Destination: string;
      Source: string;
    }
    export interface ResponseParameterList {
      ResponseParameters?: ResponseParameter[];
    }
    export interface TlsConfig {
      ServerNameToVerify?: string;
    }
  }
  export interface IntegrationResponse {
    ApiId: string;
    ContentHandlingStrategy?: string;
    IntegrationId: string;
    IntegrationResponseKey: string;
    ResponseParameters?: any;
    ResponseTemplates?: any;
    TemplateSelectionExpression?: string;
  }
  export interface Model {
    ApiId: string;
    ContentType?: string;
    Description?: string;
    Name: string;
    Schema: any;
  }
  export interface Route {
    ApiId: string;
    ApiKeyRequired?: boolean;
    AuthorizationScopes?: string[];
    AuthorizationType?: string;
    AuthorizerId?: string;
    ModelSelectionExpression?: string;
    OperationName?: string;
    RequestModels?: any;
    RequestParameters?: any;
    RouteKey: string;
    RouteResponseSelectionExpression?: string;
    Target?: string;
  }
  export namespace Route {
    export interface Attr {}
    export interface ParameterConstraints {
      Required: boolean;
    }
  }
  export interface RouteResponse {
    ApiId: string;
    ModelSelectionExpression?: string;
    ResponseModels?: any;
    ResponseParameters?: any;
    RouteId: string;
    RouteResponseKey: string;
  }
  export namespace RouteResponse {
    export interface Attr {}
    export interface ParameterConstraints {
      Required: boolean;
    }
  }
  export interface Stage {
    AccessLogSettings?: Stage.AccessLogSettings;
    AccessPolicyId?: string;
    ApiId: string;
    AutoDeploy?: boolean;
    ClientCertificateId?: string;
    DefaultRouteSettings?: Stage.RouteSettings;
    DeploymentId?: string;
    Description?: string;
    RouteSettings?: any;
    StageName: string;
    StageVariables?: any;
    Tags?: any;
  }
  export namespace Stage {
    export interface Attr {}
    export interface AccessLogSettings {
      DestinationArn?: string;
      Format?: string;
    }
    export interface RouteSettings {
      DataTraceEnabled?: boolean;
      DetailedMetricsEnabled?: boolean;
      LoggingLevel?: string;
      ThrottlingBurstLimit?: number;
      ThrottlingRateLimit?: number;
    }
  }
  export interface VpcLink {
    Name: string;
    SecurityGroupIds?: string[];
    SubnetIds: string[];
    Tags?: Record<string, string>;
  }
}
export namespace AppConfig {
  export interface Application {
    Description?: string;
    Name: string;
    Tags?: Application.Tags[];
  }
  export namespace Application {
    export interface Attr {}
    export interface Tags {
      Key?: string;
      Value?: string;
    }
  }
  export interface ConfigurationProfile {
    ApplicationId: string;
    Description?: string;
    LocationUri: string;
    Name: string;
    RetrievalRoleArn?: string;
    Tags?: ConfigurationProfile.Tags[];
    Type?: string;
    Validators?: ConfigurationProfile.Validators[];
  }
  export namespace ConfigurationProfile {
    export interface Attr {}
    export interface Tags {
      Key?: string;
      Value?: string;
    }
    export interface Validators {
      Content?: string;
      Type?: string;
    }
  }
  export interface Deployment {
    ApplicationId: string;
    ConfigurationProfileId: string;
    ConfigurationVersion: string;
    DeploymentStrategyId: string;
    Description?: string;
    EnvironmentId: string;
    Tags?: Deployment.Tags[];
  }
  export namespace Deployment {
    export interface Attr {}
    export interface Tags {
      Key?: string;
      Value?: string;
    }
  }
  export interface DeploymentStrategy {
    DeploymentDurationInMinutes: number;
    Description?: string;
    FinalBakeTimeInMinutes?: number;
    GrowthFactor: number;
    GrowthType?: string;
    Name: string;
    ReplicateTo: string;
    Tags?: DeploymentStrategy.Tags[];
  }
  export namespace DeploymentStrategy {
    export interface Attr {}
    export interface Tags {
      Key?: string;
      Value?: string;
    }
  }
  export interface Environment {
    ApplicationId: string;
    Description?: string;
    Monitors?: Environment.Monitors[];
    Name: string;
    Tags?: Environment.Tags[];
  }
  export namespace Environment {
    export interface Attr {}
    export interface Monitors {
      AlarmArn?: string;
      AlarmRoleArn?: string;
    }
    export interface Tags {
      Key?: string;
      Value?: string;
    }
  }
  export interface HostedConfigurationVersion {
    ApplicationId: string;
    ConfigurationProfileId: string;
    Content: string;
    ContentType: string;
    Description?: string;
    LatestVersionNumber?: number;
  }
}
export namespace AppFlow {
  export interface Connector {
    ConnectorLabel?: string;
    ConnectorProvisioningConfig: Connector.ConnectorProvisioningConfig;
    ConnectorProvisioningType: string;
    Description?: string;
  }
  export namespace Connector {
    export interface Attr {
      ConnectorArn: string;
    }
    export interface ConnectorProvisioningConfig {
      Lambda?: LambdaConnectorProvisioningConfig;
    }
    export interface LambdaConnectorProvisioningConfig {
      LambdaArn: string;
    }
  }
  export interface ConnectorProfile {
    ConnectionMode: string;
    ConnectorLabel?: string;
    ConnectorProfileConfig?: ConnectorProfile.ConnectorProfileConfig;
    ConnectorProfileName: string;
    ConnectorType: string;
    KMSArn?: string;
  }
  export namespace ConnectorProfile {
    export interface Attr {
      ConnectorProfileArn: string;
      CredentialsArn: string;
    }
    export interface AmplitudeConnectorProfileCredentials {
      ApiKey: string;
      SecretKey: string;
    }
    export interface ApiKeyCredentials {
      ApiKey: string;
      ApiSecretKey?: string;
    }
    export interface BasicAuthCredentials {
      Password: string;
      Username: string;
    }
    export interface ConnectorOAuthRequest {
      AuthCode?: string;
      RedirectUri?: string;
    }
    export interface ConnectorProfileConfig {
      ConnectorProfileCredentials?: ConnectorProfileCredentials;
      ConnectorProfileProperties?: ConnectorProfileProperties;
    }
    export interface ConnectorProfileCredentials {
      Amplitude?: AmplitudeConnectorProfileCredentials;
      CustomConnector?: CustomConnectorProfileCredentials;
      Datadog?: DatadogConnectorProfileCredentials;
      Dynatrace?: DynatraceConnectorProfileCredentials;
      GoogleAnalytics?: GoogleAnalyticsConnectorProfileCredentials;
      InforNexus?: InforNexusConnectorProfileCredentials;
      Marketo?: MarketoConnectorProfileCredentials;
      Redshift?: RedshiftConnectorProfileCredentials;
      SAPOData?: SAPODataConnectorProfileCredentials;
      Salesforce?: SalesforceConnectorProfileCredentials;
      ServiceNow?: ServiceNowConnectorProfileCredentials;
      Singular?: SingularConnectorProfileCredentials;
      Slack?: SlackConnectorProfileCredentials;
      Snowflake?: SnowflakeConnectorProfileCredentials;
      Trendmicro?: TrendmicroConnectorProfileCredentials;
      Veeva?: VeevaConnectorProfileCredentials;
      Zendesk?: ZendeskConnectorProfileCredentials;
    }
    export interface ConnectorProfileProperties {
      CustomConnector?: CustomConnectorProfileProperties;
      Datadog?: DatadogConnectorProfileProperties;
      Dynatrace?: DynatraceConnectorProfileProperties;
      InforNexus?: InforNexusConnectorProfileProperties;
      Marketo?: MarketoConnectorProfileProperties;
      Redshift?: RedshiftConnectorProfileProperties;
      SAPOData?: SAPODataConnectorProfileProperties;
      Salesforce?: SalesforceConnectorProfileProperties;
      ServiceNow?: ServiceNowConnectorProfileProperties;
      Slack?: SlackConnectorProfileProperties;
      Snowflake?: SnowflakeConnectorProfileProperties;
      Veeva?: VeevaConnectorProfileProperties;
      Zendesk?: ZendeskConnectorProfileProperties;
    }
    export interface CustomAuthCredentials {
      CredentialsMap?: Record<string, string>;
      CustomAuthenticationType: string;
    }
    export interface CustomConnectorProfileCredentials {
      ApiKey?: ApiKeyCredentials;
      AuthenticationType: string;
      Basic?: BasicAuthCredentials;
      Custom?: CustomAuthCredentials;
      Oauth2?: OAuth2Credentials;
    }
    export interface CustomConnectorProfileProperties {
      OAuth2Properties?: OAuth2Properties;
      ProfileProperties?: Record<string, string>;
    }
    export interface DatadogConnectorProfileCredentials {
      ApiKey: string;
      ApplicationKey: string;
    }
    export interface DatadogConnectorProfileProperties {
      InstanceUrl: string;
    }
    export interface DynatraceConnectorProfileCredentials {
      ApiToken: string;
    }
    export interface DynatraceConnectorProfileProperties {
      InstanceUrl: string;
    }
    export interface GoogleAnalyticsConnectorProfileCredentials {
      AccessToken?: string;
      ClientId: string;
      ClientSecret: string;
      ConnectorOAuthRequest?: ConnectorOAuthRequest;
      RefreshToken?: string;
    }
    export interface InforNexusConnectorProfileCredentials {
      AccessKeyId: string;
      Datakey: string;
      SecretAccessKey: string;
      UserId: string;
    }
    export interface InforNexusConnectorProfileProperties {
      InstanceUrl: string;
    }
    export interface MarketoConnectorProfileCredentials {
      AccessToken?: string;
      ClientId: string;
      ClientSecret: string;
      ConnectorOAuthRequest?: ConnectorOAuthRequest;
    }
    export interface MarketoConnectorProfileProperties {
      InstanceUrl: string;
    }
    export interface OAuth2Credentials {
      AccessToken?: string;
      ClientId?: string;
      ClientSecret?: string;
      OAuthRequest?: ConnectorOAuthRequest;
      RefreshToken?: string;
    }
    export interface OAuth2Properties {
      OAuth2GrantType?: string;
      TokenUrl?: string;
      TokenUrlCustomProperties?: Record<string, string>;
    }
    export interface OAuthCredentials {
      AccessToken?: string;
      ClientId?: string;
      ClientSecret?: string;
      ConnectorOAuthRequest?: ConnectorOAuthRequest;
      RefreshToken?: string;
    }
    export interface OAuthProperties {
      AuthCodeUrl?: string;
      OAuthScopes?: string[];
      TokenUrl?: string;
    }
    export interface RedshiftConnectorProfileCredentials {
      Password?: string;
      Username?: string;
    }
    export interface RedshiftConnectorProfileProperties {
      BucketName: string;
      BucketPrefix?: string;
      ClusterIdentifier?: string;
      DataApiRoleArn?: string;
      DatabaseName?: string;
      DatabaseUrl?: string;
      IsRedshiftServerless?: boolean;
      RoleArn: string;
      WorkgroupName?: string;
    }
    export interface SAPODataConnectorProfileCredentials {
      BasicAuthCredentials?: BasicAuthCredentials;
      OAuthCredentials?: OAuthCredentials;
    }
    export interface SAPODataConnectorProfileProperties {
      ApplicationHostUrl?: string;
      ApplicationServicePath?: string;
      ClientNumber?: string;
      LogonLanguage?: string;
      OAuthProperties?: OAuthProperties;
      PortNumber?: number;
      PrivateLinkServiceName?: string;
    }
    export interface SalesforceConnectorProfileCredentials {
      AccessToken?: string;
      ClientCredentialsArn?: string;
      ConnectorOAuthRequest?: ConnectorOAuthRequest;
      RefreshToken?: string;
    }
    export interface SalesforceConnectorProfileProperties {
      InstanceUrl?: string;
      isSandboxEnvironment?: boolean;
    }
    export interface ServiceNowConnectorProfileCredentials {
      Password: string;
      Username: string;
    }
    export interface ServiceNowConnectorProfileProperties {
      InstanceUrl: string;
    }
    export interface SingularConnectorProfileCredentials {
      ApiKey: string;
    }
    export interface SlackConnectorProfileCredentials {
      AccessToken?: string;
      ClientId: string;
      ClientSecret: string;
      ConnectorOAuthRequest?: ConnectorOAuthRequest;
    }
    export interface SlackConnectorProfileProperties {
      InstanceUrl: string;
    }
    export interface SnowflakeConnectorProfileCredentials {
      Password: string;
      Username: string;
    }
    export interface SnowflakeConnectorProfileProperties {
      AccountName?: string;
      BucketName: string;
      BucketPrefix?: string;
      PrivateLinkServiceName?: string;
      Region?: string;
      Stage: string;
      Warehouse: string;
    }
    export interface TrendmicroConnectorProfileCredentials {
      ApiSecretKey: string;
    }
    export interface VeevaConnectorProfileCredentials {
      Password: string;
      Username: string;
    }
    export interface VeevaConnectorProfileProperties {
      InstanceUrl: string;
    }
    export interface ZendeskConnectorProfileCredentials {
      AccessToken?: string;
      ClientId: string;
      ClientSecret: string;
      ConnectorOAuthRequest?: ConnectorOAuthRequest;
    }
    export interface ZendeskConnectorProfileProperties {
      InstanceUrl: string;
    }
  }
  export interface Flow {
    Description?: string;
    DestinationFlowConfigList: Flow.DestinationFlowConfig[];
    FlowName: string;
    KMSArn?: string;
    MetadataCatalogConfig?: Flow.MetadataCatalogConfig;
    SourceFlowConfig: Flow.SourceFlowConfig;
    Tags?: Tag[];
    Tasks: Flow.Task[];
    TriggerConfig: Flow.TriggerConfig;
  }
  export namespace Flow {
    export interface Attr {
      FlowArn: string;
    }
    export interface AggregationConfig {
      AggregationType?: string;
      TargetFileSize?: number;
    }
    export interface AmplitudeSourceProperties {
      Object: string;
    }
    export interface ConnectorOperator {
      Amplitude?: string;
      CustomConnector?: string;
      Datadog?: string;
      Dynatrace?: string;
      GoogleAnalytics?: string;
      InforNexus?: string;
      Marketo?: string;
      S3?: string;
      SAPOData?: string;
      Salesforce?: string;
      ServiceNow?: string;
      Singular?: string;
      Slack?: string;
      Trendmicro?: string;
      Veeva?: string;
      Zendesk?: string;
    }
    export interface CustomConnectorDestinationProperties {
      CustomProperties?: Record<string, string>;
      EntityName: string;
      ErrorHandlingConfig?: ErrorHandlingConfig;
      IdFieldNames?: string[];
      WriteOperationType?: string;
    }
    export interface CustomConnectorSourceProperties {
      CustomProperties?: Record<string, string>;
      EntityName: string;
    }
    export interface DatadogSourceProperties {
      Object: string;
    }
    export interface DestinationConnectorProperties {
      CustomConnector?: CustomConnectorDestinationProperties;
      EventBridge?: EventBridgeDestinationProperties;
      LookoutMetrics?: LookoutMetricsDestinationProperties;
      Marketo?: MarketoDestinationProperties;
      Redshift?: RedshiftDestinationProperties;
      S3?: S3DestinationProperties;
      SAPOData?: SAPODataDestinationProperties;
      Salesforce?: SalesforceDestinationProperties;
      Snowflake?: SnowflakeDestinationProperties;
      Upsolver?: UpsolverDestinationProperties;
      Zendesk?: ZendeskDestinationProperties;
    }
    export interface DestinationFlowConfig {
      ApiVersion?: string;
      ConnectorProfileName?: string;
      ConnectorType: string;
      DestinationConnectorProperties: DestinationConnectorProperties;
    }
    export interface DynatraceSourceProperties {
      Object: string;
    }
    export interface ErrorHandlingConfig {
      BucketName?: string;
      BucketPrefix?: string;
      FailOnFirstError?: boolean;
    }
    export interface EventBridgeDestinationProperties {
      ErrorHandlingConfig?: ErrorHandlingConfig;
      Object: string;
    }
    export interface GlueDataCatalog {
      DatabaseName: string;
      RoleArn: string;
      TablePrefix: string;
    }
    export interface GoogleAnalyticsSourceProperties {
      Object: string;
    }
    export interface IncrementalPullConfig {
      DatetimeTypeFieldName?: string;
    }
    export interface InforNexusSourceProperties {
      Object: string;
    }
    export interface LookoutMetricsDestinationProperties {
      Object?: string;
    }
    export interface MarketoDestinationProperties {
      ErrorHandlingConfig?: ErrorHandlingConfig;
      Object: string;
    }
    export interface MarketoSourceProperties {
      Object: string;
    }
    export interface MetadataCatalogConfig {
      GlueDataCatalog?: GlueDataCatalog;
    }
    export interface PrefixConfig {
      PathPrefixHierarchy?: string[];
      PrefixFormat?: string;
      PrefixType?: string;
    }
    export interface RedshiftDestinationProperties {
      BucketPrefix?: string;
      ErrorHandlingConfig?: ErrorHandlingConfig;
      IntermediateBucketName: string;
      Object: string;
    }
    export interface S3DestinationProperties {
      BucketName: string;
      BucketPrefix?: string;
      S3OutputFormatConfig?: S3OutputFormatConfig;
    }
    export interface S3InputFormatConfig {
      S3InputFileType?: string;
    }
    export interface S3OutputFormatConfig {
      AggregationConfig?: AggregationConfig;
      FileType?: string;
      PrefixConfig?: PrefixConfig;
      PreserveSourceDataTyping?: boolean;
    }
    export interface S3SourceProperties {
      BucketName: string;
      BucketPrefix: string;
      S3InputFormatConfig?: S3InputFormatConfig;
    }
    export interface SAPODataDestinationProperties {
      ErrorHandlingConfig?: ErrorHandlingConfig;
      IdFieldNames?: string[];
      ObjectPath: string;
      SuccessResponseHandlingConfig?: SuccessResponseHandlingConfig;
      WriteOperationType?: string;
    }
    export interface SAPODataSourceProperties {
      ObjectPath: string;
    }
    export interface SalesforceDestinationProperties {
      DataTransferApi?: string;
      ErrorHandlingConfig?: ErrorHandlingConfig;
      IdFieldNames?: string[];
      Object: string;
      WriteOperationType?: string;
    }
    export interface SalesforceSourceProperties {
      DataTransferApi?: string;
      EnableDynamicFieldUpdate?: boolean;
      IncludeDeletedRecords?: boolean;
      Object: string;
    }
    export interface ScheduledTriggerProperties {
      DataPullMode?: string;
      FirstExecutionFrom?: number;
      FlowErrorDeactivationThreshold?: number;
      ScheduleEndTime?: number;
      ScheduleExpression: string;
      ScheduleOffset?: number;
      ScheduleStartTime?: number;
      TimeZone?: string;
    }
    export interface ServiceNowSourceProperties {
      Object: string;
    }
    export interface SingularSourceProperties {
      Object: string;
    }
    export interface SlackSourceProperties {
      Object: string;
    }
    export interface SnowflakeDestinationProperties {
      BucketPrefix?: string;
      ErrorHandlingConfig?: ErrorHandlingConfig;
      IntermediateBucketName: string;
      Object: string;
    }
    export interface SourceConnectorProperties {
      Amplitude?: AmplitudeSourceProperties;
      CustomConnector?: CustomConnectorSourceProperties;
      Datadog?: DatadogSourceProperties;
      Dynatrace?: DynatraceSourceProperties;
      GoogleAnalytics?: GoogleAnalyticsSourceProperties;
      InforNexus?: InforNexusSourceProperties;
      Marketo?: MarketoSourceProperties;
      S3?: S3SourceProperties;
      SAPOData?: SAPODataSourceProperties;
      Salesforce?: SalesforceSourceProperties;
      ServiceNow?: ServiceNowSourceProperties;
      Singular?: SingularSourceProperties;
      Slack?: SlackSourceProperties;
      Trendmicro?: TrendmicroSourceProperties;
      Veeva?: VeevaSourceProperties;
      Zendesk?: ZendeskSourceProperties;
    }
    export interface SourceFlowConfig {
      ApiVersion?: string;
      ConnectorProfileName?: string;
      ConnectorType: string;
      IncrementalPullConfig?: IncrementalPullConfig;
      SourceConnectorProperties: SourceConnectorProperties;
    }
    export interface SuccessResponseHandlingConfig {
      BucketName?: string;
      BucketPrefix?: string;
    }
    export interface Task {
      ConnectorOperator?: ConnectorOperator;
      DestinationField?: string;
      SourceFields: string[];
      TaskProperties?: TaskPropertiesObject[];
      TaskType: string;
    }
    export interface TaskPropertiesObject {
      Key: string;
      Value: string;
    }
    export interface TrendmicroSourceProperties {
      Object: string;
    }
    export interface TriggerConfig {
      TriggerProperties?: ScheduledTriggerProperties;
      TriggerType: string;
    }
    export interface UpsolverDestinationProperties {
      BucketName: string;
      BucketPrefix?: string;
      S3OutputFormatConfig: UpsolverS3OutputFormatConfig;
    }
    export interface UpsolverS3OutputFormatConfig {
      AggregationConfig?: AggregationConfig;
      FileType?: string;
      PrefixConfig: PrefixConfig;
    }
    export interface VeevaSourceProperties {
      DocumentType?: string;
      IncludeAllVersions?: boolean;
      IncludeRenditions?: boolean;
      IncludeSourceFiles?: boolean;
      Object: string;
    }
    export interface ZendeskDestinationProperties {
      ErrorHandlingConfig?: ErrorHandlingConfig;
      IdFieldNames?: string[];
      Object: string;
      WriteOperationType?: string;
    }
    export interface ZendeskSourceProperties {
      Object: string;
    }
  }
}
export namespace AppIntegrations {
  export interface DataIntegration {
    Description?: string;
    KmsKey: string;
    Name: string;
    ScheduleConfig: DataIntegration.ScheduleConfig;
    SourceURI: string;
    Tags?: Tag[];
  }
  export namespace DataIntegration {
    export interface Attr {
      DataIntegrationArn: string;
      Id: string;
    }
    export interface ScheduleConfig {
      FirstExecutionFrom: string;
      Object: string;
      ScheduleExpression: string;
    }
  }
  export interface EventIntegration {
    Description?: string;
    EventBridgeBus: string;
    EventFilter: EventIntegration.EventFilter;
    Name: string;
    Tags?: Tag[];
  }
  export namespace EventIntegration {
    export interface Attr {
      Associations: EventIntegrationAssociation[];
      EventIntegrationArn: string;
    }
    export interface EventFilter {
      Source: string;
    }
    export interface EventIntegrationAssociation {
      ClientAssociationMetadata?: Metadata[];
      ClientId?: string;
      EventBridgeRuleName?: string;
      EventIntegrationAssociationArn?: string;
      EventIntegrationAssociationId?: string;
    }
    export interface Metadata {
      Key: string;
      Value: string;
    }
  }
}
export namespace AppMesh {
  export interface GatewayRoute {
    GatewayRouteName?: string;
    MeshName: string;
    MeshOwner?: string;
    Spec: GatewayRoute.GatewayRouteSpec;
    Tags?: Tag[];
    VirtualGatewayName: string;
  }
  export namespace GatewayRoute {
    export interface Attr {
      Arn: string;
      GatewayRouteName: string;
      MeshName: string;
      MeshOwner: string;
      ResourceOwner: string;
      Uid: string;
      VirtualGatewayName: string;
    }
    export interface GatewayRouteHostnameMatch {
      Exact?: string;
      Suffix?: string;
    }
    export interface GatewayRouteHostnameRewrite {
      DefaultTargetHostname?: string;
    }
    export interface GatewayRouteMetadataMatch {
      Exact?: string;
      Prefix?: string;
      Range?: GatewayRouteRangeMatch;
      Regex?: string;
      Suffix?: string;
    }
    export interface GatewayRouteRangeMatch {
      End: number;
      Start: number;
    }
    export interface GatewayRouteSpec {
      GrpcRoute?: GrpcGatewayRoute;
      Http2Route?: HttpGatewayRoute;
      HttpRoute?: HttpGatewayRoute;
      Priority?: number;
    }
    export interface GatewayRouteTarget {
      Port?: number;
      VirtualService: GatewayRouteVirtualService;
    }
    export interface GatewayRouteVirtualService {
      VirtualServiceName: string;
    }
    export interface GrpcGatewayRoute {
      Action: GrpcGatewayRouteAction;
      Match: GrpcGatewayRouteMatch;
    }
    export interface GrpcGatewayRouteAction {
      Rewrite?: GrpcGatewayRouteRewrite;
      Target: GatewayRouteTarget;
    }
    export interface GrpcGatewayRouteMatch {
      Hostname?: GatewayRouteHostnameMatch;
      Metadata?: GrpcGatewayRouteMetadata[];
      Port?: number;
      ServiceName?: string;
    }
    export interface GrpcGatewayRouteMetadata {
      Invert?: boolean;
      Match?: GatewayRouteMetadataMatch;
      Name: string;
    }
    export interface GrpcGatewayRouteRewrite {
      Hostname?: GatewayRouteHostnameRewrite;
    }
    export interface HttpGatewayRoute {
      Action: HttpGatewayRouteAction;
      Match: HttpGatewayRouteMatch;
    }
    export interface HttpGatewayRouteAction {
      Rewrite?: HttpGatewayRouteRewrite;
      Target: GatewayRouteTarget;
    }
    export interface HttpGatewayRouteHeader {
      Invert?: boolean;
      Match?: HttpGatewayRouteHeaderMatch;
      Name: string;
    }
    export interface HttpGatewayRouteHeaderMatch {
      Exact?: string;
      Prefix?: string;
      Range?: GatewayRouteRangeMatch;
      Regex?: string;
      Suffix?: string;
    }
    export interface HttpGatewayRouteMatch {
      Headers?: HttpGatewayRouteHeader[];
      Hostname?: GatewayRouteHostnameMatch;
      Method?: string;
      Path?: HttpPathMatch;
      Port?: number;
      Prefix?: string;
      QueryParameters?: QueryParameter[];
    }
    export interface HttpGatewayRoutePathRewrite {
      Exact?: string;
    }
    export interface HttpGatewayRoutePrefixRewrite {
      DefaultPrefix?: string;
      Value?: string;
    }
    export interface HttpGatewayRouteRewrite {
      Hostname?: GatewayRouteHostnameRewrite;
      Path?: HttpGatewayRoutePathRewrite;
      Prefix?: HttpGatewayRoutePrefixRewrite;
    }
    export interface HttpPathMatch {
      Exact?: string;
      Regex?: string;
    }
    export interface HttpQueryParameterMatch {
      Exact?: string;
    }
    export interface QueryParameter {
      Match?: HttpQueryParameterMatch;
      Name: string;
    }
  }
  export interface Mesh {
    MeshName?: string;
    Spec?: Mesh.MeshSpec;
    Tags?: Tag[];
  }
  export namespace Mesh {
    export interface Attr {
      Arn: string;
      MeshName: string;
      MeshOwner: string;
      ResourceOwner: string;
      Uid: string;
    }
    export interface EgressFilter {
      Type: string;
    }
    export interface MeshServiceDiscovery {
      IpPreference?: string;
    }
    export interface MeshSpec {
      EgressFilter?: EgressFilter;
      ServiceDiscovery?: MeshServiceDiscovery;
    }
  }
  export interface Route {
    MeshName: string;
    MeshOwner?: string;
    RouteName?: string;
    Spec: Route.RouteSpec;
    Tags?: Tag[];
    VirtualRouterName: string;
  }
  export namespace Route {
    export interface Attr {
      Arn: string;
      MeshName: string;
      MeshOwner: string;
      ResourceOwner: string;
      RouteName: string;
      Uid: string;
      VirtualRouterName: string;
    }
    export interface Duration {
      Unit: string;
      Value: number;
    }
    export interface GrpcRetryPolicy {
      GrpcRetryEvents?: string[];
      HttpRetryEvents?: string[];
      MaxRetries: number;
      PerRetryTimeout: Duration;
      TcpRetryEvents?: string[];
    }
    export interface GrpcRoute {
      Action: GrpcRouteAction;
      Match: GrpcRouteMatch;
      RetryPolicy?: GrpcRetryPolicy;
      Timeout?: GrpcTimeout;
    }
    export interface GrpcRouteAction {
      WeightedTargets: WeightedTarget[];
    }
    export interface GrpcRouteMatch {
      Metadata?: GrpcRouteMetadata[];
      MethodName?: string;
      Port?: number;
      ServiceName?: string;
    }
    export interface GrpcRouteMetadata {
      Invert?: boolean;
      Match?: GrpcRouteMetadataMatchMethod;
      Name: string;
    }
    export interface GrpcRouteMetadataMatchMethod {
      Exact?: string;
      Prefix?: string;
      Range?: MatchRange;
      Regex?: string;
      Suffix?: string;
    }
    export interface GrpcTimeout {
      Idle?: Duration;
      PerRequest?: Duration;
    }
    export interface HeaderMatchMethod {
      Exact?: string;
      Prefix?: string;
      Range?: MatchRange;
      Regex?: string;
      Suffix?: string;
    }
    export interface HttpPathMatch {
      Exact?: string;
      Regex?: string;
    }
    export interface HttpQueryParameterMatch {
      Exact?: string;
    }
    export interface HttpRetryPolicy {
      HttpRetryEvents?: string[];
      MaxRetries: number;
      PerRetryTimeout: Duration;
      TcpRetryEvents?: string[];
    }
    export interface HttpRoute {
      Action: HttpRouteAction;
      Match: HttpRouteMatch;
      RetryPolicy?: HttpRetryPolicy;
      Timeout?: HttpTimeout;
    }
    export interface HttpRouteAction {
      WeightedTargets: WeightedTarget[];
    }
    export interface HttpRouteHeader {
      Invert?: boolean;
      Match?: HeaderMatchMethod;
      Name: string;
    }
    export interface HttpRouteMatch {
      Headers?: HttpRouteHeader[];
      Method?: string;
      Path?: HttpPathMatch;
      Port?: number;
      Prefix?: string;
      QueryParameters?: QueryParameter[];
      Scheme?: string;
    }
    export interface HttpTimeout {
      Idle?: Duration;
      PerRequest?: Duration;
    }
    export interface MatchRange {
      End: number;
      Start: number;
    }
    export interface QueryParameter {
      Match?: HttpQueryParameterMatch;
      Name: string;
    }
    export interface RouteSpec {
      GrpcRoute?: GrpcRoute;
      Http2Route?: HttpRoute;
      HttpRoute?: HttpRoute;
      Priority?: number;
      TcpRoute?: TcpRoute;
    }
    export interface TcpRoute {
      Action: TcpRouteAction;
      Match?: TcpRouteMatch;
      Timeout?: TcpTimeout;
    }
    export interface TcpRouteAction {
      WeightedTargets: WeightedTarget[];
    }
    export interface TcpRouteMatch {
      Port?: number;
    }
    export interface TcpTimeout {
      Idle?: Duration;
    }
    export interface WeightedTarget {
      Port?: number;
      VirtualNode: string;
      Weight: number;
    }
  }
  export interface VirtualGateway {
    MeshName: string;
    MeshOwner?: string;
    Spec: VirtualGateway.VirtualGatewaySpec;
    Tags?: Tag[];
    VirtualGatewayName?: string;
  }
  export namespace VirtualGateway {
    export interface Attr {
      Arn: string;
      MeshName: string;
      MeshOwner: string;
      ResourceOwner: string;
      Uid: string;
      VirtualGatewayName: string;
    }
    export interface JsonFormatRef {
      Key: string;
      Value: string;
    }
    export interface LoggingFormat {
      Json?: JsonFormatRef[];
      Text?: string;
    }
    export interface SubjectAlternativeNameMatchers {
      Exact?: string[];
    }
    export interface SubjectAlternativeNames {
      Match: SubjectAlternativeNameMatchers;
    }
    export interface VirtualGatewayAccessLog {
      File?: VirtualGatewayFileAccessLog;
    }
    export interface VirtualGatewayBackendDefaults {
      ClientPolicy?: VirtualGatewayClientPolicy;
    }
    export interface VirtualGatewayClientPolicy {
      TLS?: VirtualGatewayClientPolicyTls;
    }
    export interface VirtualGatewayClientPolicyTls {
      Certificate?: VirtualGatewayClientTlsCertificate;
      Enforce?: boolean;
      Ports?: number[];
      Validation: VirtualGatewayTlsValidationContext;
    }
    export interface VirtualGatewayClientTlsCertificate {
      File?: VirtualGatewayListenerTlsFileCertificate;
      SDS?: VirtualGatewayListenerTlsSdsCertificate;
    }
    export interface VirtualGatewayConnectionPool {
      GRPC?: VirtualGatewayGrpcConnectionPool;
      HTTP?: VirtualGatewayHttpConnectionPool;
      HTTP2?: VirtualGatewayHttp2ConnectionPool;
    }
    export interface VirtualGatewayFileAccessLog {
      Format?: LoggingFormat;
      Path: string;
    }
    export interface VirtualGatewayGrpcConnectionPool {
      MaxRequests: number;
    }
    export interface VirtualGatewayHealthCheckPolicy {
      HealthyThreshold: number;
      IntervalMillis: number;
      Path?: string;
      Port?: number;
      Protocol: string;
      TimeoutMillis: number;
      UnhealthyThreshold: number;
    }
    export interface VirtualGatewayHttp2ConnectionPool {
      MaxRequests: number;
    }
    export interface VirtualGatewayHttpConnectionPool {
      MaxConnections: number;
      MaxPendingRequests?: number;
    }
    export interface VirtualGatewayListener {
      ConnectionPool?: VirtualGatewayConnectionPool;
      HealthCheck?: VirtualGatewayHealthCheckPolicy;
      PortMapping: VirtualGatewayPortMapping;
      TLS?: VirtualGatewayListenerTls;
    }
    export interface VirtualGatewayListenerTls {
      Certificate: VirtualGatewayListenerTlsCertificate;
      Mode: string;
      Validation?: VirtualGatewayListenerTlsValidationContext;
    }
    export interface VirtualGatewayListenerTlsAcmCertificate {
      CertificateArn: string;
    }
    export interface VirtualGatewayListenerTlsCertificate {
      ACM?: VirtualGatewayListenerTlsAcmCertificate;
      File?: VirtualGatewayListenerTlsFileCertificate;
      SDS?: VirtualGatewayListenerTlsSdsCertificate;
    }
    export interface VirtualGatewayListenerTlsFileCertificate {
      CertificateChain: string;
      PrivateKey: string;
    }
    export interface VirtualGatewayListenerTlsSdsCertificate {
      SecretName: string;
    }
    export interface VirtualGatewayListenerTlsValidationContext {
      SubjectAlternativeNames?: SubjectAlternativeNames;
      Trust: VirtualGatewayListenerTlsValidationContextTrust;
    }
    export interface VirtualGatewayListenerTlsValidationContextTrust {
      File?: VirtualGatewayTlsValidationContextFileTrust;
      SDS?: VirtualGatewayTlsValidationContextSdsTrust;
    }
    export interface VirtualGatewayLogging {
      AccessLog?: VirtualGatewayAccessLog;
    }
    export interface VirtualGatewayPortMapping {
      Port: number;
      Protocol: string;
    }
    export interface VirtualGatewaySpec {
      BackendDefaults?: VirtualGatewayBackendDefaults;
      Listeners: VirtualGatewayListener[];
      Logging?: VirtualGatewayLogging;
    }
    export interface VirtualGatewayTlsValidationContext {
      SubjectAlternativeNames?: SubjectAlternativeNames;
      Trust: VirtualGatewayTlsValidationContextTrust;
    }
    export interface VirtualGatewayTlsValidationContextAcmTrust {
      CertificateAuthorityArns: string[];
    }
    export interface VirtualGatewayTlsValidationContextFileTrust {
      CertificateChain: string;
    }
    export interface VirtualGatewayTlsValidationContextSdsTrust {
      SecretName: string;
    }
    export interface VirtualGatewayTlsValidationContextTrust {
      ACM?: VirtualGatewayTlsValidationContextAcmTrust;
      File?: VirtualGatewayTlsValidationContextFileTrust;
      SDS?: VirtualGatewayTlsValidationContextSdsTrust;
    }
  }
  export interface VirtualNode {
    MeshName: string;
    MeshOwner?: string;
    Spec: VirtualNode.VirtualNodeSpec;
    Tags?: Tag[];
    VirtualNodeName?: string;
  }
  export namespace VirtualNode {
    export interface Attr {
      Arn: string;
      MeshName: string;
      MeshOwner: string;
      ResourceOwner: string;
      Uid: string;
      VirtualNodeName: string;
    }
    export interface AccessLog {
      File?: FileAccessLog;
    }
    export interface AwsCloudMapInstanceAttribute {
      Key: string;
      Value: string;
    }
    export interface AwsCloudMapServiceDiscovery {
      Attributes?: AwsCloudMapInstanceAttribute[];
      IpPreference?: string;
      NamespaceName: string;
      ServiceName: string;
    }
    export interface Backend {
      VirtualService?: VirtualServiceBackend;
    }
    export interface BackendDefaults {
      ClientPolicy?: ClientPolicy;
    }
    export interface ClientPolicy {
      TLS?: ClientPolicyTls;
    }
    export interface ClientPolicyTls {
      Certificate?: ClientTlsCertificate;
      Enforce?: boolean;
      Ports?: number[];
      Validation: TlsValidationContext;
    }
    export interface ClientTlsCertificate {
      File?: ListenerTlsFileCertificate;
      SDS?: ListenerTlsSdsCertificate;
    }
    export interface DnsServiceDiscovery {
      Hostname: string;
      IpPreference?: string;
      ResponseType?: string;
    }
    export interface Duration {
      Unit: string;
      Value: number;
    }
    export interface FileAccessLog {
      Format?: LoggingFormat;
      Path: string;
    }
    export interface GrpcTimeout {
      Idle?: Duration;
      PerRequest?: Duration;
    }
    export interface HealthCheck {
      HealthyThreshold: number;
      IntervalMillis: number;
      Path?: string;
      Port?: number;
      Protocol: string;
      TimeoutMillis: number;
      UnhealthyThreshold: number;
    }
    export interface HttpTimeout {
      Idle?: Duration;
      PerRequest?: Duration;
    }
    export interface JsonFormatRef {
      Key: string;
      Value: string;
    }
    export interface Listener {
      ConnectionPool?: VirtualNodeConnectionPool;
      HealthCheck?: HealthCheck;
      OutlierDetection?: OutlierDetection;
      PortMapping: PortMapping;
      TLS?: ListenerTls;
      Timeout?: ListenerTimeout;
    }
    export interface ListenerTimeout {
      GRPC?: GrpcTimeout;
      HTTP?: HttpTimeout;
      HTTP2?: HttpTimeout;
      TCP?: TcpTimeout;
    }
    export interface ListenerTls {
      Certificate: ListenerTlsCertificate;
      Mode: string;
      Validation?: ListenerTlsValidationContext;
    }
    export interface ListenerTlsAcmCertificate {
      CertificateArn: string;
    }
    export interface ListenerTlsCertificate {
      ACM?: ListenerTlsAcmCertificate;
      File?: ListenerTlsFileCertificate;
      SDS?: ListenerTlsSdsCertificate;
    }
    export interface ListenerTlsFileCertificate {
      CertificateChain: string;
      PrivateKey: string;
    }
    export interface ListenerTlsSdsCertificate {
      SecretName: string;
    }
    export interface ListenerTlsValidationContext {
      SubjectAlternativeNames?: SubjectAlternativeNames;
      Trust: ListenerTlsValidationContextTrust;
    }
    export interface ListenerTlsValidationContextTrust {
      File?: TlsValidationContextFileTrust;
      SDS?: TlsValidationContextSdsTrust;
    }
    export interface Logging {
      AccessLog?: AccessLog;
    }
    export interface LoggingFormat {
      Json?: JsonFormatRef[];
      Text?: string;
    }
    export interface OutlierDetection {
      BaseEjectionDuration: Duration;
      Interval: Duration;
      MaxEjectionPercent: number;
      MaxServerErrors: number;
    }
    export interface PortMapping {
      Port: number;
      Protocol: string;
    }
    export interface ServiceDiscovery {
      AWSCloudMap?: AwsCloudMapServiceDiscovery;
      DNS?: DnsServiceDiscovery;
    }
    export interface SubjectAlternativeNameMatchers {
      Exact?: string[];
    }
    export interface SubjectAlternativeNames {
      Match: SubjectAlternativeNameMatchers;
    }
    export interface TcpTimeout {
      Idle?: Duration;
    }
    export interface TlsValidationContext {
      SubjectAlternativeNames?: SubjectAlternativeNames;
      Trust: TlsValidationContextTrust;
    }
    export interface TlsValidationContextAcmTrust {
      CertificateAuthorityArns: string[];
    }
    export interface TlsValidationContextFileTrust {
      CertificateChain: string;
    }
    export interface TlsValidationContextSdsTrust {
      SecretName: string;
    }
    export interface TlsValidationContextTrust {
      ACM?: TlsValidationContextAcmTrust;
      File?: TlsValidationContextFileTrust;
      SDS?: TlsValidationContextSdsTrust;
    }
    export interface VirtualNodeConnectionPool {
      GRPC?: VirtualNodeGrpcConnectionPool;
      HTTP?: VirtualNodeHttpConnectionPool;
      HTTP2?: VirtualNodeHttp2ConnectionPool;
      TCP?: VirtualNodeTcpConnectionPool;
    }
    export interface VirtualNodeGrpcConnectionPool {
      MaxRequests: number;
    }
    export interface VirtualNodeHttp2ConnectionPool {
      MaxRequests: number;
    }
    export interface VirtualNodeHttpConnectionPool {
      MaxConnections: number;
      MaxPendingRequests?: number;
    }
    export interface VirtualNodeSpec {
      BackendDefaults?: BackendDefaults;
      Backends?: Backend[];
      Listeners?: Listener[];
      Logging?: Logging;
      ServiceDiscovery?: ServiceDiscovery;
    }
    export interface VirtualNodeTcpConnectionPool {
      MaxConnections: number;
    }
    export interface VirtualServiceBackend {
      ClientPolicy?: ClientPolicy;
      VirtualServiceName: string;
    }
  }
  export interface VirtualRouter {
    MeshName: string;
    MeshOwner?: string;
    Spec: VirtualRouter.VirtualRouterSpec;
    Tags?: Tag[];
    VirtualRouterName?: string;
  }
  export namespace VirtualRouter {
    export interface Attr {
      Arn: string;
      MeshName: string;
      MeshOwner: string;
      ResourceOwner: string;
      Uid: string;
      VirtualRouterName: string;
    }
    export interface PortMapping {
      Port: number;
      Protocol: string;
    }
    export interface VirtualRouterListener {
      PortMapping: PortMapping;
    }
    export interface VirtualRouterSpec {
      Listeners: VirtualRouterListener[];
    }
  }
  export interface VirtualService {
    MeshName: string;
    MeshOwner?: string;
    Spec: VirtualService.VirtualServiceSpec;
    Tags?: Tag[];
    VirtualServiceName: string;
  }
  export namespace VirtualService {
    export interface Attr {
      Arn: string;
      MeshName: string;
      MeshOwner: string;
      ResourceOwner: string;
      Uid: string;
      VirtualServiceName: string;
    }
    export interface VirtualNodeServiceProvider {
      VirtualNodeName: string;
    }
    export interface VirtualRouterServiceProvider {
      VirtualRouterName: string;
    }
    export interface VirtualServiceProvider {
      VirtualNode?: VirtualNodeServiceProvider;
      VirtualRouter?: VirtualRouterServiceProvider;
    }
    export interface VirtualServiceSpec {
      Provider?: VirtualServiceProvider;
    }
  }
}
export namespace AppRunner {
  export interface ObservabilityConfiguration {
    ObservabilityConfigurationName?: string;
    Tags?: Tag[];
    TraceConfiguration?: ObservabilityConfiguration.TraceConfiguration;
  }
  export namespace ObservabilityConfiguration {
    export interface Attr {
      Latest: boolean;
      ObservabilityConfigurationArn: string;
      ObservabilityConfigurationRevision: number;
    }
    export interface TraceConfiguration {
      Vendor: string;
    }
  }
  export interface Service {
    AutoScalingConfigurationArn?: string;
    EncryptionConfiguration?: Service.EncryptionConfiguration;
    HealthCheckConfiguration?: Service.HealthCheckConfiguration;
    InstanceConfiguration?: Service.InstanceConfiguration;
    NetworkConfiguration?: Service.NetworkConfiguration;
    ObservabilityConfiguration?: Service.ServiceObservabilityConfiguration;
    ServiceName?: string;
    SourceConfiguration: Service.SourceConfiguration;
    Tags?: Tag[];
  }
  export namespace Service {
    export interface Attr {
      ServiceArn: string;
      ServiceId: string;
      ServiceUrl: string;
      Status: string;
    }
    export interface AuthenticationConfiguration {
      AccessRoleArn?: string;
      ConnectionArn?: string;
    }
    export interface CodeConfiguration {
      CodeConfigurationValues?: CodeConfigurationValues;
      ConfigurationSource: string;
    }
    export interface CodeConfigurationValues {
      BuildCommand?: string;
      Port?: string;
      Runtime: string;
      RuntimeEnvironmentSecrets?: KeyValuePair[];
      RuntimeEnvironmentVariables?: KeyValuePair[];
      StartCommand?: string;
    }
    export interface CodeRepository {
      CodeConfiguration?: CodeConfiguration;
      RepositoryUrl: string;
      SourceCodeVersion: SourceCodeVersion;
    }
    export interface EgressConfiguration {
      EgressType: string;
      VpcConnectorArn?: string;
    }
    export interface EncryptionConfiguration {
      KmsKey: string;
    }
    export interface HealthCheckConfiguration {
      HealthyThreshold?: number;
      Interval?: number;
      Path?: string;
      Protocol?: string;
      Timeout?: number;
      UnhealthyThreshold?: number;
    }
    export interface ImageConfiguration {
      Port?: string;
      RuntimeEnvironmentSecrets?: KeyValuePair[];
      RuntimeEnvironmentVariables?: KeyValuePair[];
      StartCommand?: string;
    }
    export interface ImageRepository {
      ImageConfiguration?: ImageConfiguration;
      ImageIdentifier: string;
      ImageRepositoryType: string;
    }
    export interface IngressConfiguration {
      IsPubliclyAccessible: boolean;
    }
    export interface InstanceConfiguration {
      Cpu?: string;
      InstanceRoleArn?: string;
      Memory?: string;
    }
    export interface KeyValuePair {
      Name?: string;
      Value?: string;
    }
    export interface NetworkConfiguration {
      EgressConfiguration?: EgressConfiguration;
      IngressConfiguration?: IngressConfiguration;
    }
    export interface ServiceObservabilityConfiguration {
      ObservabilityConfigurationArn?: string;
      ObservabilityEnabled: boolean;
    }
    export interface SourceCodeVersion {
      Type: string;
      Value: string;
    }
    export interface SourceConfiguration {
      AuthenticationConfiguration?: AuthenticationConfiguration;
      AutoDeploymentsEnabled?: boolean;
      CodeRepository?: CodeRepository;
      ImageRepository?: ImageRepository;
    }
  }
  export interface VpcConnector {
    SecurityGroups?: string[];
    Subnets: string[];
    Tags?: Tag[];
    VpcConnectorName?: string;
  }
  export interface VpcIngressConnection {
    IngressVpcConfiguration: VpcIngressConnection.IngressVpcConfiguration;
    ServiceArn: string;
    Tags?: Tag[];
    VpcIngressConnectionName?: string;
  }
  export namespace VpcIngressConnection {
    export interface Attr {
      DomainName: string;
      Status: string;
      VpcIngressConnectionArn: string;
    }
    export interface IngressVpcConfiguration {
      VpcEndpointId: string;
      VpcId: string;
    }
  }
}
export namespace AppStream {
  export interface AppBlock {
    Description?: string;
    DisplayName?: string;
    Name: string;
    SetupScriptDetails: AppBlock.ScriptDetails;
    SourceS3Location: AppBlock.S3Location;
    Tags?: Tag[];
  }
  export namespace AppBlock {
    export interface Attr {
      Arn: string;
      CreatedTime: string;
    }
    export interface S3Location {
      S3Bucket: string;
      S3Key: string;
    }
    export interface ScriptDetails {
      ExecutableParameters?: string;
      ExecutablePath: string;
      ScriptS3Location: S3Location;
      TimeoutInSeconds: number;
    }
  }
  export interface Application {
    AppBlockArn: string;
    AttributesToDelete?: string[];
    Description?: string;
    DisplayName?: string;
    IconS3Location: Application.S3Location;
    InstanceFamilies: string[];
    LaunchParameters?: string;
    LaunchPath: string;
    Name: string;
    Platforms: string[];
    Tags?: Tag[];
    WorkingDirectory?: string;
  }
  export namespace Application {
    export interface Attr {
      Arn: string;
      CreatedTime: string;
    }
    export interface S3Location {
      S3Bucket: string;
      S3Key: string;
    }
  }
  export interface ApplicationEntitlementAssociation {
    ApplicationIdentifier: string;
    EntitlementName: string;
    StackName: string;
  }
  export interface ApplicationFleetAssociation {
    ApplicationArn: string;
    FleetName: string;
  }
  export interface DirectoryConfig {
    CertificateBasedAuthProperties?: DirectoryConfig.CertificateBasedAuthProperties;
    DirectoryName: string;
    OrganizationalUnitDistinguishedNames: string[];
    ServiceAccountCredentials: DirectoryConfig.ServiceAccountCredentials;
  }
  export namespace DirectoryConfig {
    export interface Attr {}
    export interface CertificateBasedAuthProperties {
      CertificateAuthorityArn?: string;
      Status?: string;
    }
    export interface ServiceAccountCredentials {
      AccountName: string;
      AccountPassword: string;
    }
  }
  export interface Entitlement {
    AppVisibility: string;
    Attributes: Entitlement.Attribute[];
    Description?: string;
    Name: string;
    StackName: string;
  }
  export namespace Entitlement {
    export interface Attr {
      CreatedTime: string;
      LastModifiedTime: string;
    }
    export interface Attribute {
      Name: string;
      Value: string;
    }
  }
  export interface Fleet {
    ComputeCapacity?: Fleet.ComputeCapacity;
    Description?: string;
    DisconnectTimeoutInSeconds?: number;
    DisplayName?: string;
    DomainJoinInfo?: Fleet.DomainJoinInfo;
    EnableDefaultInternetAccess?: boolean;
    FleetType?: string;
    IamRoleArn?: string;
    IdleDisconnectTimeoutInSeconds?: number;
    ImageArn?: string;
    ImageName?: string;
    InstanceType: string;
    MaxConcurrentSessions?: number;
    MaxUserDurationInSeconds?: number;
    Name: string;
    Platform?: string;
    SessionScriptS3Location?: Fleet.S3Location;
    StreamView?: string;
    Tags?: Tag[];
    UsbDeviceFilterStrings?: string[];
    VpcConfig?: Fleet.VpcConfig;
  }
  export namespace Fleet {
    export interface Attr {}
    export interface ComputeCapacity {
      DesiredInstances: number;
    }
    export interface DomainJoinInfo {
      DirectoryName?: string;
      OrganizationalUnitDistinguishedName?: string;
    }
    export interface S3Location {
      S3Bucket: string;
      S3Key: string;
    }
    export interface VpcConfig {
      SecurityGroupIds?: string[];
      SubnetIds?: string[];
    }
  }
  export interface ImageBuilder {
    AccessEndpoints?: ImageBuilder.AccessEndpoint[];
    AppstreamAgentVersion?: string;
    Description?: string;
    DisplayName?: string;
    DomainJoinInfo?: ImageBuilder.DomainJoinInfo;
    EnableDefaultInternetAccess?: boolean;
    IamRoleArn?: string;
    ImageArn?: string;
    ImageName?: string;
    InstanceType: string;
    Name: string;
    Tags?: Tag[];
    VpcConfig?: ImageBuilder.VpcConfig;
  }
  export namespace ImageBuilder {
    export interface Attr {
      StreamingUrl: string;
    }
    export interface AccessEndpoint {
      EndpointType: string;
      VpceId: string;
    }
    export interface DomainJoinInfo {
      DirectoryName?: string;
      OrganizationalUnitDistinguishedName?: string;
    }
    export interface VpcConfig {
      SecurityGroupIds?: string[];
      SubnetIds?: string[];
    }
  }
  export interface Stack {
    AccessEndpoints?: Stack.AccessEndpoint[];
    ApplicationSettings?: Stack.ApplicationSettings;
    AttributesToDelete?: string[];
    DeleteStorageConnectors?: boolean;
    Description?: string;
    DisplayName?: string;
    EmbedHostDomains?: string[];
    FeedbackURL?: string;
    Name?: string;
    RedirectURL?: string;
    StorageConnectors?: Stack.StorageConnector[];
    StreamingExperienceSettings?: Stack.StreamingExperienceSettings;
    Tags?: Tag[];
    UserSettings?: Stack.UserSetting[];
  }
  export namespace Stack {
    export interface Attr {}
    export interface AccessEndpoint {
      EndpointType: string;
      VpceId: string;
    }
    export interface ApplicationSettings {
      Enabled: boolean;
      SettingsGroup?: string;
    }
    export interface StorageConnector {
      ConnectorType: string;
      Domains?: string[];
      ResourceIdentifier?: string;
    }
    export interface StreamingExperienceSettings {
      PreferredProtocol?: string;
    }
    export interface UserSetting {
      Action: string;
      Permission: string;
    }
  }
  export interface StackFleetAssociation {
    FleetName: string;
    StackName: string;
  }
  export interface StackUserAssociation {
    AuthenticationType: string;
    SendEmailNotification?: boolean;
    StackName: string;
    UserName: string;
  }
  export interface User {
    AuthenticationType: string;
    FirstName?: string;
    LastName?: string;
    MessageAction?: string;
    UserName: string;
  }
}
export namespace AppSync {
  export interface ApiCache {
    ApiCachingBehavior: string;
    ApiId: string;
    AtRestEncryptionEnabled?: boolean;
    TransitEncryptionEnabled?: boolean;
    Ttl: number;
    Type: string;
  }
  export interface ApiKey {
    ApiId: string;
    ApiKeyId?: string;
    Description?: string;
    Expires?: number;
  }
  export interface DataSource {
    ApiId: string;
    Description?: string;
    DynamoDBConfig?: DataSource.DynamoDBConfig;
    ElasticsearchConfig?: DataSource.ElasticsearchConfig;
    EventBridgeConfig?: DataSource.EventBridgeConfig;
    HttpConfig?: DataSource.HttpConfig;
    LambdaConfig?: DataSource.LambdaConfig;
    Name: string;
    OpenSearchServiceConfig?: DataSource.OpenSearchServiceConfig;
    RelationalDatabaseConfig?: DataSource.RelationalDatabaseConfig;
    ServiceRoleArn?: string;
    Type: string;
  }
  export namespace DataSource {
    export interface Attr {
      DataSourceArn: string;
      Name: string;
    }
    export interface AuthorizationConfig {
      AuthorizationType: string;
      AwsIamConfig?: AwsIamConfig;
    }
    export interface AwsIamConfig {
      SigningRegion?: string;
      SigningServiceName?: string;
    }
    export interface DeltaSyncConfig {
      BaseTableTTL: string;
      DeltaSyncTableName: string;
      DeltaSyncTableTTL: string;
    }
    export interface DynamoDBConfig {
      AwsRegion: string;
      DeltaSyncConfig?: DeltaSyncConfig;
      TableName: string;
      UseCallerCredentials?: boolean;
      Versioned?: boolean;
    }
    export interface ElasticsearchConfig {
      AwsRegion: string;
      Endpoint: string;
    }
    export interface EventBridgeConfig {
      EventBusArn: string;
    }
    export interface HttpConfig {
      AuthorizationConfig?: AuthorizationConfig;
      Endpoint: string;
    }
    export interface LambdaConfig {
      LambdaFunctionArn: string;
    }
    export interface OpenSearchServiceConfig {
      AwsRegion: string;
      Endpoint: string;
    }
    export interface RdsHttpEndpointConfig {
      AwsRegion: string;
      AwsSecretStoreArn: string;
      DatabaseName?: string;
      DbClusterIdentifier: string;
      Schema?: string;
    }
    export interface RelationalDatabaseConfig {
      RdsHttpEndpointConfig?: RdsHttpEndpointConfig;
      RelationalDatabaseSourceType: string;
    }
  }
  export interface DomainName {
    CertificateArn: string;
    Description?: string;
    DomainName: string;
  }
  export interface DomainNameApiAssociation {
    ApiId: string;
    DomainName: string;
  }
  export interface FunctionConfiguration {
    ApiId: string;
    Code?: string;
    CodeS3Location?: string;
    DataSourceName: string;
    Description?: string;
    FunctionVersion?: string;
    MaxBatchSize?: number;
    Name: string;
    RequestMappingTemplate?: string;
    RequestMappingTemplateS3Location?: string;
    ResponseMappingTemplate?: string;
    ResponseMappingTemplateS3Location?: string;
    Runtime?: FunctionConfiguration.AppSyncRuntime;
    SyncConfig?: FunctionConfiguration.SyncConfig;
  }
  export namespace FunctionConfiguration {
    export interface Attr {
      DataSourceName: string;
      FunctionArn: string;
      FunctionId: string;
      Name: string;
    }
    export interface AppSyncRuntime {
      Name: string;
      RuntimeVersion: string;
    }
    export interface LambdaConflictHandlerConfig {
      LambdaConflictHandlerArn?: string;
    }
    export interface SyncConfig {
      ConflictDetection: string;
      ConflictHandler?: string;
      LambdaConflictHandlerConfig?: LambdaConflictHandlerConfig;
    }
  }
  export interface GraphQLApi {
    AdditionalAuthenticationProviders?: GraphQLApi.AdditionalAuthenticationProvider[];
    AuthenticationType: string;
    LambdaAuthorizerConfig?: GraphQLApi.LambdaAuthorizerConfig;
    LogConfig?: GraphQLApi.LogConfig;
    Name: string;
    OpenIDConnectConfig?: GraphQLApi.OpenIDConnectConfig;
    Tags?: Tag[];
    UserPoolConfig?: GraphQLApi.UserPoolConfig;
    XrayEnabled?: boolean;
  }
  export namespace GraphQLApi {
    export interface Attr {
      ApiId: string;
      Arn: string;
      GraphQLUrl: string;
    }
    export interface AdditionalAuthenticationProvider {
      AuthenticationType: string;
      LambdaAuthorizerConfig?: LambdaAuthorizerConfig;
      OpenIDConnectConfig?: OpenIDConnectConfig;
      UserPoolConfig?: CognitoUserPoolConfig;
    }
    export interface CognitoUserPoolConfig {
      AppIdClientRegex?: string;
      AwsRegion?: string;
      UserPoolId?: string;
    }
    export interface LambdaAuthorizerConfig {
      AuthorizerResultTtlInSeconds?: number;
      AuthorizerUri?: string;
      IdentityValidationExpression?: string;
    }
    export interface LogConfig {
      CloudWatchLogsRoleArn?: string;
      ExcludeVerboseContent?: boolean;
      FieldLogLevel?: string;
    }
    export interface OpenIDConnectConfig {
      AuthTTL?: number;
      ClientId?: string;
      IatTTL?: number;
      Issuer?: string;
    }
    export interface UserPoolConfig {
      AppIdClientRegex?: string;
      AwsRegion?: string;
      DefaultAction?: string;
      UserPoolId?: string;
    }
  }
  export interface GraphQLSchema {
    ApiId: string;
    Definition?: string;
    DefinitionS3Location?: string;
  }
  export interface Resolver {
    ApiId: string;
    CachingConfig?: Resolver.CachingConfig;
    Code?: string;
    CodeS3Location?: string;
    DataSourceName?: string;
    FieldName: string;
    Kind?: string;
    MaxBatchSize?: number;
    PipelineConfig?: Resolver.PipelineConfig;
    RequestMappingTemplate?: string;
    RequestMappingTemplateS3Location?: string;
    ResponseMappingTemplate?: string;
    ResponseMappingTemplateS3Location?: string;
    Runtime?: Resolver.AppSyncRuntime;
    SyncConfig?: Resolver.SyncConfig;
    TypeName: string;
  }
  export namespace Resolver {
    export interface Attr {
      FieldName: string;
      ResolverArn: string;
      TypeName: string;
    }
    export interface AppSyncRuntime {
      Name: string;
      RuntimeVersion: string;
    }
    export interface CachingConfig {
      CachingKeys?: string[];
      Ttl: number;
    }
    export interface LambdaConflictHandlerConfig {
      LambdaConflictHandlerArn?: string;
    }
    export interface PipelineConfig {
      Functions?: string[];
    }
    export interface SyncConfig {
      ConflictDetection: string;
      ConflictHandler?: string;
      LambdaConflictHandlerConfig?: LambdaConflictHandlerConfig;
    }
  }
}
export namespace ApplicationAutoScaling {
  export interface ScalableTarget {
    MaxCapacity: number;
    MinCapacity: number;
    ResourceId: string;
    RoleARN: string;
    ScalableDimension: string;
    ScheduledActions?: ScalableTarget.ScheduledAction[];
    ServiceNamespace: string;
    SuspendedState?: ScalableTarget.SuspendedState;
  }
  export namespace ScalableTarget {
    export interface Attr {}
    export interface ScalableTargetAction {
      MaxCapacity?: number;
      MinCapacity?: number;
    }
    export interface ScheduledAction {
      EndTime?: string;
      ScalableTargetAction?: ScalableTargetAction;
      Schedule: string;
      ScheduledActionName: string;
      StartTime?: string;
      Timezone?: string;
    }
    export interface SuspendedState {
      DynamicScalingInSuspended?: boolean;
      DynamicScalingOutSuspended?: boolean;
      ScheduledScalingSuspended?: boolean;
    }
  }
  export interface ScalingPolicy {
    PolicyName: string;
    PolicyType: string;
    ResourceId?: string;
    ScalableDimension?: string;
    ScalingTargetId?: string;
    ServiceNamespace?: string;
    StepScalingPolicyConfiguration?: ScalingPolicy.StepScalingPolicyConfiguration;
    TargetTrackingScalingPolicyConfiguration?: ScalingPolicy.TargetTrackingScalingPolicyConfiguration;
  }
  export namespace ScalingPolicy {
    export interface Attr {}
    export interface CustomizedMetricSpecification {
      Dimensions?: MetricDimension[];
      MetricName: string;
      Namespace: string;
      Statistic: string;
      Unit?: string;
    }
    export interface MetricDimension {
      Name: string;
      Value: string;
    }
    export interface PredefinedMetricSpecification {
      PredefinedMetricType: string;
      ResourceLabel?: string;
    }
    export interface StepAdjustment {
      MetricIntervalLowerBound?: number;
      MetricIntervalUpperBound?: number;
      ScalingAdjustment: number;
    }
    export interface StepScalingPolicyConfiguration {
      AdjustmentType?: string;
      Cooldown?: number;
      MetricAggregationType?: string;
      MinAdjustmentMagnitude?: number;
      StepAdjustments?: StepAdjustment[];
    }
    export interface TargetTrackingScalingPolicyConfiguration {
      CustomizedMetricSpecification?: CustomizedMetricSpecification;
      DisableScaleIn?: boolean;
      PredefinedMetricSpecification?: PredefinedMetricSpecification;
      ScaleInCooldown?: number;
      ScaleOutCooldown?: number;
      TargetValue: number;
    }
  }
}
export namespace ApplicationInsights {
  export interface Application {
    AutoConfigurationEnabled?: boolean;
    CWEMonitorEnabled?: boolean;
    ComponentMonitoringSettings?: Application.ComponentMonitoringSetting[];
    CustomComponents?: Application.CustomComponent[];
    GroupingType?: string;
    LogPatternSets?: Application.LogPatternSet[];
    OpsCenterEnabled?: boolean;
    OpsItemSNSTopicArn?: string;
    ResourceGroupName: string;
    Tags?: Tag[];
  }
  export namespace Application {
    export interface Attr {
      ApplicationARN: string;
    }
    export interface Alarm {
      AlarmName: string;
      Severity?: string;
    }
    export interface AlarmMetric {
      AlarmMetricName: string;
    }
    export interface ComponentConfiguration {
      ConfigurationDetails?: ConfigurationDetails;
      SubComponentTypeConfigurations?: SubComponentTypeConfiguration[];
    }
    export interface ComponentMonitoringSetting {
      ComponentARN?: string;
      ComponentConfigurationMode: string;
      ComponentName?: string;
      CustomComponentConfiguration?: ComponentConfiguration;
      DefaultOverwriteComponentConfiguration?: ComponentConfiguration;
      Tier: string;
    }
    export interface ConfigurationDetails {
      AlarmMetrics?: AlarmMetric[];
      Alarms?: Alarm[];
      HAClusterPrometheusExporter?: HAClusterPrometheusExporter;
      HANAPrometheusExporter?: HANAPrometheusExporter;
      JMXPrometheusExporter?: JMXPrometheusExporter;
      Logs?: Log[];
      WindowsEvents?: WindowsEvent[];
    }
    export interface CustomComponent {
      ComponentName: string;
      ResourceList: string[];
    }
    export interface HAClusterPrometheusExporter {
      PrometheusPort?: string;
    }
    export interface HANAPrometheusExporter {
      AgreeToInstallHANADBClient: boolean;
      HANAPort: string;
      HANASID: string;
      HANASecretName: string;
      PrometheusPort?: string;
    }
    export interface JMXPrometheusExporter {
      HostPort?: string;
      JMXURL?: string;
      PrometheusPort?: string;
    }
    export interface Log {
      Encoding?: string;
      LogGroupName?: string;
      LogPath?: string;
      LogType: string;
      PatternSet?: string;
    }
    export interface LogPattern {
      Pattern: string;
      PatternName: string;
      Rank: number;
    }
    export interface LogPatternSet {
      LogPatterns: LogPattern[];
      PatternSetName: string;
    }
    export interface SubComponentConfigurationDetails {
      AlarmMetrics?: AlarmMetric[];
      Logs?: Log[];
      WindowsEvents?: WindowsEvent[];
    }
    export interface SubComponentTypeConfiguration {
      SubComponentConfigurationDetails: SubComponentConfigurationDetails;
      SubComponentType: string;
    }
    export interface WindowsEvent {
      EventLevels: string[];
      EventName: string;
      LogGroupName: string;
      PatternSet?: string;
    }
  }
}
export namespace Athena {
  export interface DataCatalog {
    Description?: string;
    Name: string;
    Parameters?: Record<string, string>;
    Tags?: Tag[];
    Type: string;
  }
  export interface NamedQuery {
    Database: string;
    Description?: string;
    Name?: string;
    QueryString: string;
    WorkGroup?: string;
  }
  export interface PreparedStatement {
    Description?: string;
    QueryStatement: string;
    StatementName: string;
    WorkGroup: string;
  }
  export interface WorkGroup {
    Description?: string;
    Name: string;
    RecursiveDeleteOption?: boolean;
    State?: string;
    Tags?: Tag[];
    WorkGroupConfiguration?: WorkGroup.WorkGroupConfiguration;
  }
  export namespace WorkGroup {
    export interface Attr {
      CreationTime: string;
      "WorkGroupConfiguration.EngineVersion.EffectiveEngineVersion": string;
    }
    export interface EncryptionConfiguration {
      EncryptionOption: string;
      KmsKey?: string;
    }
    export interface EngineVersion {
      EffectiveEngineVersion?: string;
      SelectedEngineVersion?: string;
    }
    export interface ResultConfiguration {
      EncryptionConfiguration?: EncryptionConfiguration;
      OutputLocation?: string;
    }
    export interface WorkGroupConfiguration {
      BytesScannedCutoffPerQuery?: number;
      EnforceWorkGroupConfiguration?: boolean;
      EngineVersion?: EngineVersion;
      PublishCloudWatchMetricsEnabled?: boolean;
      RequesterPaysEnabled?: boolean;
      ResultConfiguration?: ResultConfiguration;
    }
  }
}
export namespace AuditManager {
  export interface Assessment {
    AssessmentReportsDestination?: Assessment.AssessmentReportsDestination;
    AwsAccount?: Assessment.AWSAccount;
    Delegations?: Assessment.Delegation[];
    Description?: string;
    FrameworkId?: string;
    Name?: string;
    Roles?: Assessment.Role[];
    Scope?: Assessment.Scope;
    Status?: string;
    Tags?: Tag[];
  }
  export namespace Assessment {
    export interface Attr {
      Arn: string;
      AssessmentId: string;
      CreationTime: number;
    }
    export interface AWSAccount {
      EmailAddress?: string;
      Id?: string;
      Name?: string;
    }
    export interface AWSService {
      ServiceName?: string;
    }
    export interface AssessmentReportsDestination {
      Destination?: string;
      DestinationType?: string;
    }
    export interface Delegation {
      AssessmentId?: string;
      AssessmentName?: string;
      Comment?: string;
      ControlSetId?: string;
      CreatedBy?: string;
      CreationTime?: number;
      Id?: string;
      LastUpdated?: number;
      RoleArn?: string;
      RoleType?: string;
      Status?: string;
    }
    export interface Role {
      RoleArn?: string;
      RoleType?: string;
    }
    export interface Scope {
      AwsAccounts?: AWSAccount[];
      AwsServices?: AWSService[];
    }
  }
}
export namespace AutoScaling {
  export interface AutoScalingGroup {
    AutoScalingGroupName?: string;
    AvailabilityZones?: string[];
    CapacityRebalance?: boolean;
    Context?: string;
    Cooldown?: string;
    DefaultInstanceWarmup?: number;
    DesiredCapacity?: string;
    DesiredCapacityType?: string;
    HealthCheckGracePeriod?: number;
    HealthCheckType?: string;
    InstanceId?: string;
    LaunchConfigurationName?: string;
    LaunchTemplate?: AutoScalingGroup.LaunchTemplateSpecification;
    LifecycleHookSpecificationList?: AutoScalingGroup.LifecycleHookSpecification[];
    LoadBalancerNames?: string[];
    MaxInstanceLifetime?: number;
    MaxSize: string;
    MetricsCollection?: AutoScalingGroup.MetricsCollection[];
    MinSize: string;
    MixedInstancesPolicy?: AutoScalingGroup.MixedInstancesPolicy;
    NewInstancesProtectedFromScaleIn?: boolean;
    NotificationConfigurations?: AutoScalingGroup.NotificationConfiguration[];
    PlacementGroup?: string;
    ServiceLinkedRoleARN?: string;
    Tags?: AutoScalingGroup.TagProperty[];
    TargetGroupARNs?: string[];
    TerminationPolicies?: string[];
    VPCZoneIdentifier?: string[];
  }
  export namespace AutoScalingGroup {
    export interface Attr {}
    export interface AcceleratorCountRequest {
      Max?: number;
      Min?: number;
    }
    export interface AcceleratorTotalMemoryMiBRequest {
      Max?: number;
      Min?: number;
    }
    export interface BaselineEbsBandwidthMbpsRequest {
      Max?: number;
      Min?: number;
    }
    export interface InstanceRequirements {
      AcceleratorCount?: AcceleratorCountRequest;
      AcceleratorManufacturers?: string[];
      AcceleratorNames?: string[];
      AcceleratorTotalMemoryMiB?: AcceleratorTotalMemoryMiBRequest;
      AcceleratorTypes?: string[];
      AllowedInstanceTypes?: string[];
      BareMetal?: string;
      BaselineEbsBandwidthMbps?: BaselineEbsBandwidthMbpsRequest;
      BurstablePerformance?: string;
      CpuManufacturers?: string[];
      ExcludedInstanceTypes?: string[];
      InstanceGenerations?: string[];
      LocalStorage?: string;
      LocalStorageTypes?: string[];
      MemoryGiBPerVCpu?: MemoryGiBPerVCpuRequest;
      MemoryMiB?: MemoryMiBRequest;
      NetworkBandwidthGbps?: NetworkBandwidthGbpsRequest;
      NetworkInterfaceCount?: NetworkInterfaceCountRequest;
      OnDemandMaxPricePercentageOverLowestPrice?: number;
      RequireHibernateSupport?: boolean;
      SpotMaxPricePercentageOverLowestPrice?: number;
      TotalLocalStorageGB?: TotalLocalStorageGBRequest;
      VCpuCount?: VCpuCountRequest;
    }
    export interface InstancesDistribution {
      OnDemandAllocationStrategy?: string;
      OnDemandBaseCapacity?: number;
      OnDemandPercentageAboveBaseCapacity?: number;
      SpotAllocationStrategy?: string;
      SpotInstancePools?: number;
      SpotMaxPrice?: string;
    }
    export interface LaunchTemplate {
      LaunchTemplateSpecification: LaunchTemplateSpecification;
      Overrides?: LaunchTemplateOverrides[];
    }
    export interface LaunchTemplateOverrides {
      InstanceRequirements?: InstanceRequirements;
      InstanceType?: string;
      LaunchTemplateSpecification?: LaunchTemplateSpecification;
      WeightedCapacity?: string;
    }
    export interface LaunchTemplateSpecification {
      LaunchTemplateId?: string;
      LaunchTemplateName?: string;
      Version: string;
    }
    export interface LifecycleHookSpecification {
      DefaultResult?: string;
      HeartbeatTimeout?: number;
      LifecycleHookName: string;
      LifecycleTransition: string;
      NotificationMetadata?: string;
      NotificationTargetARN?: string;
      RoleARN?: string;
    }
    export interface MemoryGiBPerVCpuRequest {
      Max?: number;
      Min?: number;
    }
    export interface MemoryMiBRequest {
      Max?: number;
      Min?: number;
    }
    export interface MetricsCollection {
      Granularity: string;
      Metrics?: string[];
    }
    export interface MixedInstancesPolicy {
      InstancesDistribution?: InstancesDistribution;
      LaunchTemplate: LaunchTemplate;
    }
    export interface NetworkBandwidthGbpsRequest {
      Max?: number;
      Min?: number;
    }
    export interface NetworkInterfaceCountRequest {
      Max?: number;
      Min?: number;
    }
    export interface NotificationConfiguration {
      NotificationTypes?: string[];
      TopicARN: string;
    }
    export interface TagProperty {
      Key: string;
      PropagateAtLaunch: boolean;
      Value: string;
    }
    export interface TotalLocalStorageGBRequest {
      Max?: number;
      Min?: number;
    }
    export interface VCpuCountRequest {
      Max?: number;
      Min?: number;
    }
  }
  export interface LaunchConfiguration {
    AssociatePublicIpAddress?: boolean;
    BlockDeviceMappings?: LaunchConfiguration.BlockDeviceMapping[];
    ClassicLinkVPCId?: string;
    ClassicLinkVPCSecurityGroups?: string[];
    EbsOptimized?: boolean;
    IamInstanceProfile?: string;
    ImageId: string;
    InstanceId?: string;
    InstanceMonitoring?: boolean;
    InstanceType: string;
    KernelId?: string;
    KeyName?: string;
    LaunchConfigurationName?: string;
    MetadataOptions?: LaunchConfiguration.MetadataOptions;
    PlacementTenancy?: string;
    RamDiskId?: string;
    SecurityGroups?: string[];
    SpotPrice?: string;
    UserData?: string;
  }
  export namespace LaunchConfiguration {
    export interface Attr {}
    export interface BlockDevice {
      DeleteOnTermination?: boolean;
      Encrypted?: boolean;
      Iops?: number;
      SnapshotId?: string;
      Throughput?: number;
      VolumeSize?: number;
      VolumeType?: string;
    }
    export interface BlockDeviceMapping {
      DeviceName: string;
      Ebs?: BlockDevice;
      NoDevice?: boolean;
      VirtualName?: string;
    }
    export interface MetadataOptions {
      HttpEndpoint?: string;
      HttpPutResponseHopLimit?: number;
      HttpTokens?: string;
    }
  }
  export interface LifecycleHook {
    AutoScalingGroupName: string;
    DefaultResult?: string;
    HeartbeatTimeout?: number;
    LifecycleHookName?: string;
    LifecycleTransition: string;
    NotificationMetadata?: string;
    NotificationTargetARN?: string;
    RoleARN?: string;
  }
  export interface ScalingPolicy {
    AdjustmentType?: string;
    AutoScalingGroupName: string;
    Cooldown?: string;
    EstimatedInstanceWarmup?: number;
    MetricAggregationType?: string;
    MinAdjustmentMagnitude?: number;
    PolicyType?: string;
    PredictiveScalingConfiguration?: ScalingPolicy.PredictiveScalingConfiguration;
    ScalingAdjustment?: number;
    StepAdjustments?: ScalingPolicy.StepAdjustment[];
    TargetTrackingConfiguration?: ScalingPolicy.TargetTrackingConfiguration;
  }
  export namespace ScalingPolicy {
    export interface Attr {
      Arn: string;
      PolicyName: string;
    }
    export interface CustomizedMetricSpecification {
      Dimensions?: MetricDimension[];
      MetricName: string;
      Namespace: string;
      Statistic: string;
      Unit?: string;
    }
    export interface Metric {
      Dimensions?: MetricDimension[];
      MetricName: string;
      Namespace: string;
    }
    export interface MetricDataQuery {
      Expression?: string;
      Id: string;
      Label?: string;
      MetricStat?: MetricStat;
      ReturnData?: boolean;
    }
    export interface MetricDimension {
      Name: string;
      Value: string;
    }
    export interface MetricStat {
      Metric: Metric;
      Stat: string;
      Unit?: string;
    }
    export interface PredefinedMetricSpecification {
      PredefinedMetricType: string;
      ResourceLabel?: string;
    }
    export interface PredictiveScalingConfiguration {
      MaxCapacityBreachBehavior?: string;
      MaxCapacityBuffer?: number;
      MetricSpecifications: PredictiveScalingMetricSpecification[];
      Mode?: string;
      SchedulingBufferTime?: number;
    }
    export interface PredictiveScalingCustomizedCapacityMetric {
      MetricDataQueries: MetricDataQuery[];
    }
    export interface PredictiveScalingCustomizedLoadMetric {
      MetricDataQueries: MetricDataQuery[];
    }
    export interface PredictiveScalingCustomizedScalingMetric {
      MetricDataQueries: MetricDataQuery[];
    }
    export interface PredictiveScalingMetricSpecification {
      CustomizedCapacityMetricSpecification?: PredictiveScalingCustomizedCapacityMetric;
      CustomizedLoadMetricSpecification?: PredictiveScalingCustomizedLoadMetric;
      CustomizedScalingMetricSpecification?: PredictiveScalingCustomizedScalingMetric;
      PredefinedLoadMetricSpecification?: PredictiveScalingPredefinedLoadMetric;
      PredefinedMetricPairSpecification?: PredictiveScalingPredefinedMetricPair;
      PredefinedScalingMetricSpecification?: PredictiveScalingPredefinedScalingMetric;
      TargetValue: number;
    }
    export interface PredictiveScalingPredefinedLoadMetric {
      PredefinedMetricType: string;
      ResourceLabel?: string;
    }
    export interface PredictiveScalingPredefinedMetricPair {
      PredefinedMetricType: string;
      ResourceLabel?: string;
    }
    export interface PredictiveScalingPredefinedScalingMetric {
      PredefinedMetricType: string;
      ResourceLabel?: string;
    }
    export interface StepAdjustment {
      MetricIntervalLowerBound?: number;
      MetricIntervalUpperBound?: number;
      ScalingAdjustment: number;
    }
    export interface TargetTrackingConfiguration {
      CustomizedMetricSpecification?: CustomizedMetricSpecification;
      DisableScaleIn?: boolean;
      PredefinedMetricSpecification?: PredefinedMetricSpecification;
      TargetValue: number;
    }
  }
  export interface ScheduledAction {
    AutoScalingGroupName: string;
    DesiredCapacity?: number;
    EndTime?: string;
    MaxSize?: number;
    MinSize?: number;
    Recurrence?: string;
    StartTime?: string;
    TimeZone?: string;
  }
  export interface WarmPool {
    AutoScalingGroupName: string;
    InstanceReusePolicy?: WarmPool.InstanceReusePolicy;
    MaxGroupPreparedCapacity?: number;
    MinSize?: number;
    PoolState?: string;
  }
  export namespace WarmPool {
    export interface Attr {}
    export interface InstanceReusePolicy {
      ReuseOnScaleIn?: boolean;
    }
  }
}
export namespace AutoScalingPlans {
  export interface ScalingPlan {
    ApplicationSource: ScalingPlan.ApplicationSource;
    ScalingInstructions: ScalingPlan.ScalingInstruction[];
  }
  export namespace ScalingPlan {
    export interface Attr {
      ScalingPlanName: string;
      ScalingPlanVersion: string;
    }
    export interface ApplicationSource {
      CloudFormationStackARN?: string;
      TagFilters?: TagFilter[];
    }
    export interface CustomizedLoadMetricSpecification {
      Dimensions?: MetricDimension[];
      MetricName: string;
      Namespace: string;
      Statistic: string;
      Unit?: string;
    }
    export interface CustomizedScalingMetricSpecification {
      Dimensions?: MetricDimension[];
      MetricName: string;
      Namespace: string;
      Statistic: string;
      Unit?: string;
    }
    export interface MetricDimension {
      Name: string;
      Value: string;
    }
    export interface PredefinedLoadMetricSpecification {
      PredefinedLoadMetricType: string;
      ResourceLabel?: string;
    }
    export interface PredefinedScalingMetricSpecification {
      PredefinedScalingMetricType: string;
      ResourceLabel?: string;
    }
    export interface ScalingInstruction {
      CustomizedLoadMetricSpecification?: CustomizedLoadMetricSpecification;
      DisableDynamicScaling?: boolean;
      MaxCapacity: number;
      MinCapacity: number;
      PredefinedLoadMetricSpecification?: PredefinedLoadMetricSpecification;
      PredictiveScalingMaxCapacityBehavior?: string;
      PredictiveScalingMaxCapacityBuffer?: number;
      PredictiveScalingMode?: string;
      ResourceId: string;
      ScalableDimension: string;
      ScalingPolicyUpdateBehavior?: string;
      ScheduledActionBufferTime?: number;
      ServiceNamespace: string;
      TargetTrackingConfigurations: TargetTrackingConfiguration[];
    }
    export interface TagFilter {
      Key: string;
      Values?: string[];
    }
    export interface TargetTrackingConfiguration {
      CustomizedScalingMetricSpecification?: CustomizedScalingMetricSpecification;
      DisableScaleIn?: boolean;
      EstimatedInstanceWarmup?: number;
      PredefinedScalingMetricSpecification?: PredefinedScalingMetricSpecification;
      ScaleInCooldown?: number;
      ScaleOutCooldown?: number;
      TargetValue: number;
    }
  }
}
export namespace Backup {
  export interface BackupPlan {
    BackupPlan: BackupPlan.BackupPlanResourceType;
    BackupPlanTags?: Record<string, string>;
  }
  export namespace BackupPlan {
    export interface Attr {
      BackupPlanArn: string;
      BackupPlanId: string;
      VersionId: string;
    }
    export interface AdvancedBackupSettingResourceType {
      BackupOptions: any;
      ResourceType: string;
    }
    export interface BackupPlanResourceType {
      AdvancedBackupSettings?: AdvancedBackupSettingResourceType[];
      BackupPlanName: string;
      BackupPlanRule: BackupRuleResourceType[];
    }
    export interface BackupRuleResourceType {
      CompletionWindowMinutes?: number;
      CopyActions?: CopyActionResourceType[];
      EnableContinuousBackup?: boolean;
      Lifecycle?: LifecycleResourceType;
      RecoveryPointTags?: Record<string, string>;
      RuleName: string;
      ScheduleExpression?: string;
      StartWindowMinutes?: number;
      TargetBackupVault: string;
    }
    export interface CopyActionResourceType {
      DestinationBackupVaultArn: string;
      Lifecycle?: LifecycleResourceType;
    }
    export interface LifecycleResourceType {
      DeleteAfterDays?: number;
      MoveToColdStorageAfterDays?: number;
    }
  }
  export interface BackupSelection {
    BackupPlanId: string;
    BackupSelection: BackupSelection.BackupSelectionResourceType;
  }
  export namespace BackupSelection {
    export interface Attr {
      BackupPlanId: string;
      Id: string;
      SelectionId: string;
    }
    export interface BackupSelectionResourceType {
      Conditions?: any;
      IamRoleArn: string;
      ListOfTags?: ConditionResourceType[];
      NotResources?: string[];
      Resources?: string[];
      SelectionName: string;
    }
    export interface ConditionParameter {
      ConditionKey?: string;
      ConditionValue?: string;
    }
    export interface ConditionResourceType {
      ConditionKey: string;
      ConditionType: string;
      ConditionValue: string;
    }
    export interface Conditions {
      StringEquals?: ConditionParameter[];
      StringLike?: ConditionParameter[];
      StringNotEquals?: ConditionParameter[];
      StringNotLike?: ConditionParameter[];
    }
  }
  export interface BackupVault {
    AccessPolicy?: any;
    BackupVaultName: string;
    BackupVaultTags?: Record<string, string>;
    EncryptionKeyArn?: string;
    LockConfiguration?: BackupVault.LockConfigurationType;
    Notifications?: BackupVault.NotificationObjectType;
  }
  export namespace BackupVault {
    export interface Attr {
      BackupVaultArn: string;
      BackupVaultName: string;
    }
    export interface LockConfigurationType {
      ChangeableForDays?: number;
      MaxRetentionDays?: number;
      MinRetentionDays: number;
    }
    export interface NotificationObjectType {
      BackupVaultEvents: string[];
      SNSTopicArn: string;
    }
  }
  export interface Framework {
    FrameworkControls: Framework.FrameworkControl[];
    FrameworkDescription?: string;
    FrameworkName?: string;
    FrameworkTags?: Tag[];
  }
  export namespace Framework {
    export interface Attr {
      CreationTime: string;
      DeploymentStatus: string;
      FrameworkArn: string;
      FrameworkStatus: string;
    }
    export interface ControlInputParameter {
      ParameterName: string;
      ParameterValue: string;
    }
    export interface ControlScope {
      ComplianceResourceIds?: string[];
      ComplianceResourceTypes?: string[];
      Tags?: Tag[];
    }
    export interface FrameworkControl {
      ControlInputParameters?: ControlInputParameter[];
      ControlName: string;
      ControlScope?: any;
    }
  }
  export interface ReportPlan {
    ReportDeliveryChannel: any;
    ReportPlanDescription?: string;
    ReportPlanName?: string;
    ReportPlanTags?: Tag[];
    ReportSetting: any;
  }
  export namespace ReportPlan {
    export interface Attr {
      ReportPlanArn: string;
    }
    export interface ReportDeliveryChannel {
      Formats?: string[];
      S3BucketName: string;
      S3KeyPrefix?: string;
    }
    export interface ReportSetting {
      Accounts?: string[];
      FrameworkArns?: string[];
      OrganizationUnits?: string[];
      Regions?: string[];
      ReportTemplate: string;
    }
  }
}
export namespace Batch {
  export interface ComputeEnvironment {
    ComputeEnvironmentName?: string;
    ComputeResources?: ComputeEnvironment.ComputeResources;
    EksConfiguration?: ComputeEnvironment.EksConfiguration;
    ReplaceComputeEnvironment?: boolean;
    ServiceRole?: string;
    State?: string;
    Tags?: Record<string, string>;
    Type: string;
    UnmanagedvCpus?: number;
    UpdatePolicy?: ComputeEnvironment.UpdatePolicy;
  }
  export namespace ComputeEnvironment {
    export interface Attr {
      ComputeEnvironmentArn: string;
    }
    export interface ComputeResources {
      AllocationStrategy?: string;
      BidPercentage?: number;
      DesiredvCpus?: number;
      Ec2Configuration?: Ec2ConfigurationObject[];
      Ec2KeyPair?: string;
      ImageId?: string;
      InstanceRole?: string;
      InstanceTypes?: string[];
      LaunchTemplate?: LaunchTemplateSpecification;
      MaxvCpus: number;
      MinvCpus?: number;
      PlacementGroup?: string;
      SecurityGroupIds?: string[];
      SpotIamFleetRole?: string;
      Subnets: string[];
      Tags?: Record<string, string>;
      Type: string;
      UpdateToLatestImageVersion?: boolean;
    }
    export interface Ec2ConfigurationObject {
      ImageIdOverride?: string;
      ImageKubernetesVersion?: string;
      ImageType: string;
    }
    export interface EksConfiguration {
      EksClusterArn: string;
      KubernetesNamespace: string;
    }
    export interface LaunchTemplateSpecification {
      LaunchTemplateId?: string;
      LaunchTemplateName?: string;
      Version?: string;
    }
    export interface UpdatePolicy {
      JobExecutionTimeoutMinutes?: number;
      TerminateJobsOnUpdate?: boolean;
    }
  }
  export interface JobDefinition {
    ContainerProperties?: JobDefinition.ContainerProperties;
    EksProperties?: JobDefinition.EksProperties;
    JobDefinitionName?: string;
    NodeProperties?: JobDefinition.NodeProperties;
    Parameters?: any;
    PlatformCapabilities?: string[];
    PropagateTags?: boolean;
    RetryStrategy?: JobDefinition.RetryStrategy;
    SchedulingPriority?: number;
    Tags?: any;
    Timeout?: JobDefinition.Timeout;
    Type: string;
  }
  export namespace JobDefinition {
    export interface Attr {}
    export interface AuthorizationConfig {
      AccessPointId?: string;
      Iam?: string;
    }
    export interface ContainerProperties {
      Command?: string[];
      Environment?: Environment[];
      ExecutionRoleArn?: string;
      FargatePlatformConfiguration?: FargatePlatformConfiguration;
      Image: string;
      InstanceType?: string;
      JobRoleArn?: string;
      LinuxParameters?: LinuxParameters;
      LogConfiguration?: LogConfiguration;
      Memory?: number;
      MountPoints?: MountPoints[];
      NetworkConfiguration?: NetworkConfiguration;
      Privileged?: boolean;
      ReadonlyRootFilesystem?: boolean;
      ResourceRequirements?: ResourceRequirement[];
      Secrets?: Secret[];
      Ulimits?: Ulimit[];
      User?: string;
      Vcpus?: number;
      Volumes?: Volumes[];
    }
    export interface Device {
      ContainerPath?: string;
      HostPath?: string;
      Permissions?: string[];
    }
    export interface EfsVolumeConfiguration {
      AuthorizationConfig?: AuthorizationConfig;
      FileSystemId: string;
      RootDirectory?: string;
      TransitEncryption?: string;
      TransitEncryptionPort?: number;
    }
    export interface EksContainer {
      Args?: string[];
      Command?: string[];
      Env?: EksContainerEnvironmentVariable[];
      Image: string;
      ImagePullPolicy?: string;
      Name?: string;
      Resources?: Resources;
      SecurityContext?: SecurityContext;
      VolumeMounts?: EksContainerVolumeMount[];
    }
    export interface EksContainerEnvironmentVariable {
      Name: string;
      Value?: string;
    }
    export interface EksContainerVolumeMount {
      MountPath?: string;
      Name?: string;
      ReadOnly?: boolean;
    }
    export interface EksProperties {
      PodProperties?: PodProperties;
    }
    export interface EksVolume {
      EmptyDir?: EmptyDir;
      HostPath?: HostPath;
      Name: string;
      Secret?: Secret;
    }
    export interface EmptyDir {
      Medium?: string;
      SizeLimit?: string;
    }
    export interface Environment {
      Name?: string;
      Value?: string;
    }
    export interface EvaluateOnExit {
      Action: string;
      OnExitCode?: string;
      OnReason?: string;
      OnStatusReason?: string;
    }
    export interface FargatePlatformConfiguration {
      PlatformVersion?: string;
    }
    export interface HostPath {
      Path?: string;
    }
    export interface LinuxParameters {
      Devices?: Device[];
      InitProcessEnabled?: boolean;
      MaxSwap?: number;
      SharedMemorySize?: number;
      Swappiness?: number;
      Tmpfs?: Tmpfs[];
    }
    export interface LogConfiguration {
      LogDriver: string;
      Options?: any;
      SecretOptions?: Secret[];
    }
    export interface MountPoints {
      ContainerPath?: string;
      ReadOnly?: boolean;
      SourceVolume?: string;
    }
    export interface NetworkConfiguration {
      AssignPublicIp?: string;
    }
    export interface NodeProperties {
      MainNode: number;
      NodeRangeProperties: NodeRangeProperty[];
      NumNodes: number;
    }
    export interface NodeRangeProperty {
      Container?: ContainerProperties;
      TargetNodes: string;
    }
    export interface PodProperties {
      Containers?: EksContainer[];
      DnsPolicy?: string;
      HostNetwork?: boolean;
      ServiceAccountName?: string;
      Volumes?: EksVolume[];
    }
    export interface ResourceRequirement {
      Type?: string;
      Value?: string;
    }
    export interface Resources {
      Limits?: any;
      Requests?: any;
    }
    export interface RetryStrategy {
      Attempts?: number;
      EvaluateOnExit?: EvaluateOnExit[];
    }
    export interface Secret {
      Name: string;
      ValueFrom: string;
    }
    export interface SecurityContext {
      Privileged?: boolean;
      ReadOnlyRootFilesystem?: boolean;
      RunAsGroup?: number;
      RunAsNonRoot?: boolean;
      RunAsUser?: number;
    }
    export interface Timeout {
      AttemptDurationSeconds?: number;
    }
    export interface Tmpfs {
      ContainerPath: string;
      MountOptions?: string[];
      Size: number;
    }
    export interface Ulimit {
      HardLimit: number;
      Name: string;
      SoftLimit: number;
    }
    export interface Volumes {
      EfsVolumeConfiguration?: EfsVolumeConfiguration;
      Host?: VolumesHost;
      Name?: string;
    }
    export interface VolumesHost {
      SourcePath?: string;
    }
  }
  export interface JobQueue {
    ComputeEnvironmentOrder: JobQueue.ComputeEnvironmentOrder[];
    JobQueueName?: string;
    Priority: number;
    SchedulingPolicyArn?: string;
    State?: string;
    Tags?: Record<string, string>;
  }
  export namespace JobQueue {
    export interface Attr {
      JobQueueArn: string;
    }
    export interface ComputeEnvironmentOrder {
      ComputeEnvironment: string;
      Order: number;
    }
  }
  export interface SchedulingPolicy {
    FairsharePolicy?: SchedulingPolicy.FairsharePolicy;
    Name?: string;
    Tags?: Record<string, string>;
  }
  export namespace SchedulingPolicy {
    export interface Attr {
      Arn: string;
    }
    export interface FairsharePolicy {
      ComputeReservation?: number;
      ShareDecaySeconds?: number;
      ShareDistribution?: ShareAttributes[];
    }
    export interface ShareAttributes {
      ShareIdentifier?: string;
      WeightFactor?: number;
    }
  }
}
export namespace BillingConductor {
  export interface BillingGroup {
    AccountGrouping: BillingGroup.AccountGrouping;
    ComputationPreference: BillingGroup.ComputationPreference;
    Description?: string;
    Name: string;
    PrimaryAccountId: string;
    Tags?: Tag[];
  }
  export namespace BillingGroup {
    export interface Attr {
      Arn: string;
      CreationTime: number;
      LastModifiedTime: number;
      Size: number;
      Status: string;
      StatusReason: string;
    }
    export interface AccountGrouping {
      LinkedAccountIds: string[];
    }
    export interface ComputationPreference {
      PricingPlanArn: string;
    }
  }
  export interface CustomLineItem {
    BillingGroupArn: string;
    BillingPeriodRange?: CustomLineItem.BillingPeriodRange;
    CustomLineItemChargeDetails?: CustomLineItem.CustomLineItemChargeDetails;
    Description?: string;
    Name: string;
    Tags?: Tag[];
  }
  export namespace CustomLineItem {
    export interface Attr {
      Arn: string;
      AssociationSize: number;
      CreationTime: number;
      CurrencyCode: string;
      LastModifiedTime: number;
      ProductCode: string;
    }
    export interface BillingPeriodRange {
      ExclusiveEndBillingPeriod?: string;
      InclusiveStartBillingPeriod?: string;
    }
    export interface CustomLineItemChargeDetails {
      Flat?: CustomLineItemFlatChargeDetails;
      Percentage?: CustomLineItemPercentageChargeDetails;
      Type: string;
    }
    export interface CustomLineItemFlatChargeDetails {
      ChargeValue: number;
    }
    export interface CustomLineItemPercentageChargeDetails {
      ChildAssociatedResources?: string[];
      PercentageValue: number;
    }
  }
  export interface PricingPlan {
    Description?: string;
    Name: string;
    PricingRuleArns?: string[];
    Tags?: Tag[];
  }
  export interface PricingRule {
    BillingEntity?: string;
    Description?: string;
    ModifierPercentage?: number;
    Name: string;
    Operation?: string;
    Scope: string;
    Service?: string;
    Tags?: Tag[];
    Tiering?: PricingRule.Tiering;
    Type: string;
    UsageType?: string;
  }
  export namespace PricingRule {
    export interface Attr {
      Arn: string;
      AssociatedPricingPlanCount: number;
      CreationTime: number;
      LastModifiedTime: number;
    }
    export interface FreeTier {
      Activated: boolean;
    }
    export interface Tiering {
      FreeTier?: FreeTier;
    }
  }
}
export namespace Budgets {
  export interface Budget {
    Budget: Budget.BudgetData;
    NotificationsWithSubscribers?: Budget.NotificationWithSubscribers[];
  }
  export namespace Budget {
    export interface Attr {}
    export interface AutoAdjustData {
      AutoAdjustType: string;
      HistoricalOptions?: HistoricalOptions;
    }
    export interface BudgetData {
      AutoAdjustData?: AutoAdjustData;
      BudgetLimit?: Spend;
      BudgetName?: string;
      BudgetType: string;
      CostFilters?: any;
      CostTypes?: CostTypes;
      PlannedBudgetLimits?: any;
      TimePeriod?: TimePeriod;
      TimeUnit: string;
    }
    export interface CostTypes {
      IncludeCredit?: boolean;
      IncludeDiscount?: boolean;
      IncludeOtherSubscription?: boolean;
      IncludeRecurring?: boolean;
      IncludeRefund?: boolean;
      IncludeSubscription?: boolean;
      IncludeSupport?: boolean;
      IncludeTax?: boolean;
      IncludeUpfront?: boolean;
      UseAmortized?: boolean;
      UseBlended?: boolean;
    }
    export interface HistoricalOptions {
      BudgetAdjustmentPeriod: number;
    }
    export interface Notification {
      ComparisonOperator: string;
      NotificationType: string;
      Threshold: number;
      ThresholdType?: string;
    }
    export interface NotificationWithSubscribers {
      Notification: Notification;
      Subscribers: Subscriber[];
    }
    export interface Spend {
      Amount: number;
      Unit: string;
    }
    export interface Subscriber {
      Address: string;
      SubscriptionType: string;
    }
    export interface TimePeriod {
      End?: string;
      Start?: string;
    }
  }
  export interface BudgetsAction {
    ActionThreshold: BudgetsAction.ActionThreshold;
    ActionType: string;
    ApprovalModel?: string;
    BudgetName: string;
    Definition: BudgetsAction.Definition;
    ExecutionRoleArn: string;
    NotificationType: string;
    Subscribers: BudgetsAction.Subscriber[];
  }
  export namespace BudgetsAction {
    export interface Attr {
      ActionId: string;
    }
    export interface ActionThreshold {
      Type: string;
      Value: number;
    }
    export interface Definition {
      IamActionDefinition?: IamActionDefinition;
      ScpActionDefinition?: ScpActionDefinition;
      SsmActionDefinition?: SsmActionDefinition;
    }
    export interface IamActionDefinition {
      Groups?: string[];
      PolicyArn: string;
      Roles?: string[];
      Users?: string[];
    }
    export interface ScpActionDefinition {
      PolicyId: string;
      TargetIds: string[];
    }
    export interface SsmActionDefinition {
      InstanceIds: string[];
      Region: string;
      Subtype: string;
    }
    export interface Subscriber {
      Address: string;
      Type: string;
    }
  }
}
export namespace CE {
  export interface AnomalyMonitor {
    MonitorDimension?: string;
    MonitorName: string;
    MonitorSpecification?: string;
    MonitorType: string;
    ResourceTags?: AnomalyMonitor.ResourceTag[];
  }
  export namespace AnomalyMonitor {
    export interface Attr {
      CreationDate: string;
      DimensionalValueCount: number;
      LastEvaluatedDate: string;
      LastUpdatedDate: string;
      MonitorArn: string;
    }
    export interface ResourceTag {
      Key: string;
      Value: string;
    }
  }
  export interface AnomalySubscription {
    Frequency: string;
    MonitorArnList: string[];
    ResourceTags?: AnomalySubscription.ResourceTag[];
    Subscribers: AnomalySubscription.Subscriber[];
    SubscriptionName: string;
    Threshold?: number;
    ThresholdExpression?: string;
  }
  export namespace AnomalySubscription {
    export interface Attr {
      AccountId: string;
      SubscriptionArn: string;
    }
    export interface ResourceTag {
      Key: string;
      Value: string;
    }
    export interface Subscriber {
      Address: string;
      Status?: string;
      Type: string;
    }
  }
  export interface CostCategory {
    DefaultValue?: string;
    Name: string;
    RuleVersion: string;
    Rules: string;
    SplitChargeRules?: string;
  }
}
export namespace CUR {
  export interface ReportDefinition {
    AdditionalArtifacts?: string[];
    AdditionalSchemaElements?: string[];
    BillingViewArn?: string;
    Compression: string;
    Format: string;
    RefreshClosedReports: boolean;
    ReportName: string;
    ReportVersioning: string;
    S3Bucket: string;
    S3Prefix: string;
    S3Region: string;
    TimeUnit: string;
  }
}
export namespace Cassandra {
  export interface Keyspace {
    KeyspaceName?: string;
    Tags?: Tag[];
  }
  export interface Table {
    BillingMode?: Table.BillingMode;
    ClusteringKeyColumns?: Table.ClusteringKeyColumn[];
    DefaultTimeToLive?: number;
    EncryptionSpecification?: Table.EncryptionSpecification;
    KeyspaceName: string;
    PartitionKeyColumns: Table.Column[];
    PointInTimeRecoveryEnabled?: boolean;
    RegularColumns?: Table.Column[];
    TableName?: string;
    Tags?: Tag[];
  }
  export namespace Table {
    export interface Attr {}
    export interface BillingMode {
      Mode: string;
      ProvisionedThroughput?: ProvisionedThroughput;
    }
    export interface ClusteringKeyColumn {
      Column: Column;
      OrderBy?: string;
    }
    export interface Column {
      ColumnName: string;
      ColumnType: string;
    }
    export interface EncryptionSpecification {
      EncryptionType: string;
      KmsKeyIdentifier?: string;
    }
    export interface ProvisionedThroughput {
      ReadCapacityUnits: number;
      WriteCapacityUnits: number;
    }
  }
}
export namespace CertificateManager {
  export interface Account {
    ExpiryEventsConfiguration: Account.ExpiryEventsConfiguration;
  }
  export namespace Account {
    export interface Attr {
      AccountId: string;
    }
    export interface ExpiryEventsConfiguration {
      DaysBeforeExpiry?: number;
    }
  }
  export interface Certificate {
    CertificateAuthorityArn?: string;
    CertificateTransparencyLoggingPreference?: string;
    DomainName: string;
    DomainValidationOptions?: Certificate.DomainValidationOption[];
    SubjectAlternativeNames?: string[];
    Tags?: Tag[];
    ValidationMethod?: string;
  }
  export namespace Certificate {
    export interface Attr {}
    export interface DomainValidationOption {
      DomainName: string;
      HostedZoneId?: string;
      ValidationDomain?: string;
    }
  }
}
export namespace Chatbot {
  export interface SlackChannelConfiguration {
    ConfigurationName: string;
    GuardrailPolicies?: string[];
    IamRoleArn: string;
    LoggingLevel?: string;
    SlackChannelId: string;
    SlackWorkspaceId: string;
    SnsTopicArns?: string[];
    UserRoleRequired?: boolean;
  }
}
export namespace Cloud9 {
  export interface EnvironmentEC2 {
    AutomaticStopTimeMinutes?: number;
    ConnectionType?: string;
    Description?: string;
    ImageId?: string;
    InstanceType: string;
    Name?: string;
    OwnerArn?: string;
    Repositories?: EnvironmentEC2.Repository[];
    SubnetId?: string;
    Tags?: Tag[];
  }
  export namespace EnvironmentEC2 {
    export interface Attr {
      Arn: string;
      Name: string;
    }
    export interface Repository {
      PathComponent: string;
      RepositoryUrl: string;
    }
  }
}
export namespace CloudFormation {
  export interface CustomResource {
    ServiceToken: string;
  }
  export interface HookDefaultVersion {
    TypeName?: string;
    TypeVersionArn?: string;
    VersionId?: string;
  }
  export interface HookTypeConfig {
    Configuration: string;
    ConfigurationAlias?: string;
    TypeArn?: string;
    TypeName?: string;
  }
  export interface HookVersion {
    ExecutionRoleArn?: string;
    LoggingConfig?: HookVersion.LoggingConfig;
    SchemaHandlerPackage: string;
    TypeName: string;
  }
  export namespace HookVersion {
    export interface Attr {
      Arn: string;
      IsDefaultVersion: boolean;
      TypeArn: string;
      VersionId: string;
      Visibility: string;
    }
    export interface LoggingConfig {
      LogGroupName?: string;
      LogRoleArn?: string;
    }
  }
  export interface Macro {
    Description?: string;
    FunctionName: string;
    LogGroupName?: string;
    LogRoleARN?: string;
    Name: string;
  }
  export interface ModuleDefaultVersion {
    Arn?: string;
    ModuleName?: string;
    VersionId?: string;
  }
  export interface ModuleVersion {
    ModuleName: string;
    ModulePackage: string;
  }
  export interface PublicTypeVersion {
    Arn?: string;
    LogDeliveryBucket?: string;
    PublicVersionNumber?: string;
    Type?: string;
    TypeName?: string;
  }
  export interface Publisher {
    AcceptTermsAndConditions: boolean;
    ConnectionArn?: string;
  }
  export interface ResourceDefaultVersion {
    TypeName?: string;
    TypeVersionArn?: string;
    VersionId?: string;
  }
  export interface ResourceVersion {
    ExecutionRoleArn?: string;
    LoggingConfig?: ResourceVersion.LoggingConfig;
    SchemaHandlerPackage: string;
    TypeName: string;
  }
  export namespace ResourceVersion {
    export interface Attr {
      Arn: string;
      IsDefaultVersion: boolean;
      ProvisioningType: string;
      TypeArn: string;
      VersionId: string;
      Visibility: string;
    }
    export interface LoggingConfig {
      LogGroupName?: string;
      LogRoleArn?: string;
    }
  }
  export interface Stack {
    NotificationARNs?: string[];
    Parameters?: Record<string, string>;
    Tags?: Tag[];
    TemplateURL: string;
    TimeoutInMinutes?: number;
  }
  export interface StackSet {
    AdministrationRoleARN?: string;
    AutoDeployment?: StackSet.AutoDeployment;
    CallAs?: string;
    Capabilities?: string[];
    Description?: string;
    ExecutionRoleName?: string;
    ManagedExecution?: any;
    OperationPreferences?: StackSet.OperationPreferences;
    Parameters?: StackSet.Parameter[];
    PermissionModel: string;
    StackInstancesGroup?: StackSet.StackInstances[];
    StackSetName: string;
    Tags?: Tag[];
    TemplateBody?: string;
    TemplateURL?: string;
  }
  export namespace StackSet {
    export interface Attr {
      StackSetId: string;
    }
    export interface AutoDeployment {
      Enabled?: boolean;
      RetainStacksOnAccountRemoval?: boolean;
    }
    export interface DeploymentTargets {
      AccountFilterType?: string;
      Accounts?: string[];
      OrganizationalUnitIds?: string[];
    }
    export interface ManagedExecution {
      Active?: boolean;
    }
    export interface OperationPreferences {
      FailureToleranceCount?: number;
      FailureTolerancePercentage?: number;
      MaxConcurrentCount?: number;
      MaxConcurrentPercentage?: number;
      RegionConcurrencyType?: string;
      RegionOrder?: string[];
    }
    export interface Parameter {
      ParameterKey: string;
      ParameterValue: string;
    }
    export interface StackInstances {
      DeploymentTargets: DeploymentTargets;
      ParameterOverrides?: Parameter[];
      Regions: string[];
    }
  }
  export interface TypeActivation {
    AutoUpdate?: boolean;
    ExecutionRoleArn?: string;
    LoggingConfig?: TypeActivation.LoggingConfig;
    MajorVersion?: string;
    PublicTypeArn?: string;
    PublisherId?: string;
    Type?: string;
    TypeName?: string;
    TypeNameAlias?: string;
    VersionBump?: string;
  }
  export namespace TypeActivation {
    export interface Attr {
      Arn: string;
    }
    export interface LoggingConfig {
      LogGroupName?: string;
      LogRoleArn?: string;
    }
  }
  export interface WaitCondition {
    Count?: number;
    Handle?: string;
    Timeout?: string;
  }
  export interface WaitConditionHandle {}
}
export namespace CloudFront {
  export interface CachePolicy {
    CachePolicyConfig: CachePolicy.CachePolicyConfig;
  }
  export namespace CachePolicy {
    export interface Attr {
      Id: string;
      LastModifiedTime: string;
    }
    export interface CachePolicyConfig {
      Comment?: string;
      DefaultTTL: number;
      MaxTTL: number;
      MinTTL: number;
      Name: string;
      ParametersInCacheKeyAndForwardedToOrigin: ParametersInCacheKeyAndForwardedToOrigin;
    }
    export interface CookiesConfig {
      CookieBehavior: string;
      Cookies?: string[];
    }
    export interface HeadersConfig {
      HeaderBehavior: string;
      Headers?: string[];
    }
    export interface ParametersInCacheKeyAndForwardedToOrigin {
      CookiesConfig: CookiesConfig;
      EnableAcceptEncodingBrotli?: boolean;
      EnableAcceptEncodingGzip: boolean;
      HeadersConfig: HeadersConfig;
      QueryStringsConfig: QueryStringsConfig;
    }
    export interface QueryStringsConfig {
      QueryStringBehavior: string;
      QueryStrings?: string[];
    }
  }
  export interface CloudFrontOriginAccessIdentity {
    CloudFrontOriginAccessIdentityConfig: CloudFrontOriginAccessIdentity.CloudFrontOriginAccessIdentityConfig;
  }
  export namespace CloudFrontOriginAccessIdentity {
    export interface Attr {
      Id: string;
      S3CanonicalUserId: string;
    }
    export interface CloudFrontOriginAccessIdentityConfig {
      Comment: string;
    }
  }
  export interface ContinuousDeploymentPolicy {
    ContinuousDeploymentPolicyConfig: ContinuousDeploymentPolicy.ContinuousDeploymentPolicyConfig;
  }
  export namespace ContinuousDeploymentPolicy {
    export interface Attr {
      Id: string;
      LastModifiedTime: string;
    }
    export interface ContinuousDeploymentPolicyConfig {
      Enabled: boolean;
      StagingDistributionDnsNames: string[];
      TrafficConfig?: TrafficConfig;
    }
    export interface SessionStickinessConfig {
      IdleTTL: number;
      MaximumTTL: number;
    }
    export interface SingleHeaderConfig {
      Header: string;
      Value: string;
    }
    export interface SingleWeightConfig {
      SessionStickinessConfig?: SessionStickinessConfig;
      Weight: number;
    }
    export interface TrafficConfig {
      SingleHeaderConfig?: SingleHeaderConfig;
      SingleWeightConfig?: SingleWeightConfig;
      Type: string;
    }
  }
  export interface Distribution {
    DistributionConfig: Distribution.DistributionConfig;
    Tags?: Tag[];
  }
  export namespace Distribution {
    export interface Attr {
      DomainName: string;
      Id: string;
    }
    export interface CacheBehavior {
      AllowedMethods?: string[];
      CachePolicyId?: string;
      CachedMethods?: string[];
      Compress?: boolean;
      DefaultTTL?: number;
      FieldLevelEncryptionId?: string;
      ForwardedValues?: ForwardedValues;
      FunctionAssociations?: FunctionAssociation[];
      LambdaFunctionAssociations?: LambdaFunctionAssociation[];
      MaxTTL?: number;
      MinTTL?: number;
      OriginRequestPolicyId?: string;
      PathPattern: string;
      RealtimeLogConfigArn?: string;
      ResponseHeadersPolicyId?: string;
      SmoothStreaming?: boolean;
      TargetOriginId: string;
      TrustedKeyGroups?: string[];
      TrustedSigners?: string[];
      ViewerProtocolPolicy: string;
    }
    export interface Cookies {
      Forward: string;
      WhitelistedNames?: string[];
    }
    export interface CustomErrorResponse {
      ErrorCachingMinTTL?: number;
      ErrorCode: number;
      ResponseCode?: number;
      ResponsePagePath?: string;
    }
    export interface CustomOriginConfig {
      HTTPPort?: number;
      HTTPSPort?: number;
      OriginKeepaliveTimeout?: number;
      OriginProtocolPolicy: string;
      OriginReadTimeout?: number;
      OriginSSLProtocols?: string[];
    }
    export interface DefaultCacheBehavior {
      AllowedMethods?: string[];
      CachePolicyId?: string;
      CachedMethods?: string[];
      Compress?: boolean;
      DefaultTTL?: number;
      FieldLevelEncryptionId?: string;
      ForwardedValues?: ForwardedValues;
      FunctionAssociations?: FunctionAssociation[];
      LambdaFunctionAssociations?: LambdaFunctionAssociation[];
      MaxTTL?: number;
      MinTTL?: number;
      OriginRequestPolicyId?: string;
      RealtimeLogConfigArn?: string;
      ResponseHeadersPolicyId?: string;
      SmoothStreaming?: boolean;
      TargetOriginId: string;
      TrustedKeyGroups?: string[];
      TrustedSigners?: string[];
      ViewerProtocolPolicy: string;
    }
    export interface DistributionConfig {
      Aliases?: string[];
      CNAMEs?: string[];
      CacheBehaviors?: CacheBehavior[];
      Comment?: string;
      ContinuousDeploymentPolicyId?: string;
      CustomErrorResponses?: CustomErrorResponse[];
      CustomOrigin?: LegacyCustomOrigin;
      DefaultCacheBehavior: DefaultCacheBehavior;
      DefaultRootObject?: string;
      Enabled: boolean;
      HttpVersion?: string;
      IPV6Enabled?: boolean;
      Logging?: Logging;
      OriginGroups?: OriginGroups;
      Origins?: Origin[];
      PriceClass?: string;
      Restrictions?: Restrictions;
      S3Origin?: LegacyS3Origin;
      Staging?: boolean;
      ViewerCertificate?: ViewerCertificate;
      WebACLId?: string;
    }
    export interface ForwardedValues {
      Cookies?: Cookies;
      Headers?: string[];
      QueryString: boolean;
      QueryStringCacheKeys?: string[];
    }
    export interface FunctionAssociation {
      EventType?: string;
      FunctionARN?: string;
    }
    export interface GeoRestriction {
      Locations?: string[];
      RestrictionType: string;
    }
    export interface LambdaFunctionAssociation {
      EventType?: string;
      IncludeBody?: boolean;
      LambdaFunctionARN?: string;
    }
    export interface LegacyCustomOrigin {
      DNSName: string;
      HTTPPort?: number;
      HTTPSPort?: number;
      OriginProtocolPolicy: string;
      OriginSSLProtocols: string[];
    }
    export interface LegacyS3Origin {
      DNSName: string;
      OriginAccessIdentity?: string;
    }
    export interface Logging {
      Bucket: string;
      IncludeCookies?: boolean;
      Prefix?: string;
    }
    export interface Origin {
      ConnectionAttempts?: number;
      ConnectionTimeout?: number;
      CustomOriginConfig?: CustomOriginConfig;
      DomainName: string;
      Id: string;
      OriginAccessControlId?: string;
      OriginCustomHeaders?: OriginCustomHeader[];
      OriginPath?: string;
      OriginShield?: OriginShield;
      S3OriginConfig?: S3OriginConfig;
    }
    export interface OriginCustomHeader {
      HeaderName: string;
      HeaderValue: string;
    }
    export interface OriginGroup {
      FailoverCriteria: OriginGroupFailoverCriteria;
      Id: string;
      Members: OriginGroupMembers;
    }
    export interface OriginGroupFailoverCriteria {
      StatusCodes: StatusCodes;
    }
    export interface OriginGroupMember {
      OriginId: string;
    }
    export interface OriginGroupMembers {
      Items: OriginGroupMember[];
      Quantity: number;
    }
    export interface OriginGroups {
      Items?: OriginGroup[];
      Quantity: number;
    }
    export interface OriginShield {
      Enabled?: boolean;
      OriginShieldRegion?: string;
    }
    export interface Restrictions {
      GeoRestriction: GeoRestriction;
    }
    export interface S3OriginConfig {
      OriginAccessIdentity?: string;
    }
    export interface StatusCodes {
      Items: number[];
      Quantity: number;
    }
    export interface ViewerCertificate {
      AcmCertificateArn?: string;
      CloudFrontDefaultCertificate?: boolean;
      IamCertificateId?: string;
      MinimumProtocolVersion?: string;
      SslSupportMethod?: string;
    }
  }
  export interface Function {
    AutoPublish?: boolean;
    FunctionCode: string;
    FunctionConfig: Function.FunctionConfig;
    FunctionMetadata?: Function.FunctionMetadata;
    Name: string;
  }
  export namespace Function {
    export interface Attr {
      FunctionARN: string;
      "FunctionMetadata.FunctionARN": string;
      Stage: string;
    }
    export interface FunctionConfig {
      Comment: string;
      Runtime: string;
    }
    export interface FunctionMetadata {
      FunctionARN?: string;
    }
  }
  export interface KeyGroup {
    KeyGroupConfig: KeyGroup.KeyGroupConfig;
  }
  export namespace KeyGroup {
    export interface Attr {
      Id: string;
      LastModifiedTime: string;
    }
    export interface KeyGroupConfig {
      Comment?: string;
      Items: string[];
      Name: string;
    }
  }
  export interface MonitoringSubscription {
    DistributionId: string;
    MonitoringSubscription: MonitoringSubscription.MonitoringSubscription;
  }
  export namespace MonitoringSubscription {
    export interface Attr {}
    export interface MonitoringSubscription {
      RealtimeMetricsSubscriptionConfig?: RealtimeMetricsSubscriptionConfig;
    }
    export interface RealtimeMetricsSubscriptionConfig {
      RealtimeMetricsSubscriptionStatus: string;
    }
  }
  export interface OriginAccessControl {
    OriginAccessControlConfig: OriginAccessControl.OriginAccessControlConfig;
  }
  export namespace OriginAccessControl {
    export interface Attr {
      Id: string;
    }
    export interface OriginAccessControlConfig {
      Description?: string;
      Name: string;
      OriginAccessControlOriginType: string;
      SigningBehavior: string;
      SigningProtocol: string;
    }
  }
  export interface OriginRequestPolicy {
    OriginRequestPolicyConfig: OriginRequestPolicy.OriginRequestPolicyConfig;
  }
  export namespace OriginRequestPolicy {
    export interface Attr {
      Id: string;
      LastModifiedTime: string;
    }
    export interface CookiesConfig {
      CookieBehavior: string;
      Cookies?: string[];
    }
    export interface HeadersConfig {
      HeaderBehavior: string;
      Headers?: string[];
    }
    export interface OriginRequestPolicyConfig {
      Comment?: string;
      CookiesConfig: CookiesConfig;
      HeadersConfig: HeadersConfig;
      Name: string;
      QueryStringsConfig: QueryStringsConfig;
    }
    export interface QueryStringsConfig {
      QueryStringBehavior: string;
      QueryStrings?: string[];
    }
  }
  export interface PublicKey {
    PublicKeyConfig: PublicKey.PublicKeyConfig;
  }
  export namespace PublicKey {
    export interface Attr {
      CreatedTime: string;
      Id: string;
    }
    export interface PublicKeyConfig {
      CallerReference: string;
      Comment?: string;
      EncodedKey: string;
      Name: string;
    }
  }
  export interface RealtimeLogConfig {
    EndPoints: RealtimeLogConfig.EndPoint[];
    Fields: string[];
    Name: string;
    SamplingRate: number;
  }
  export namespace RealtimeLogConfig {
    export interface Attr {
      Arn: string;
    }
    export interface EndPoint {
      KinesisStreamConfig: KinesisStreamConfig;
      StreamType: string;
    }
    export interface KinesisStreamConfig {
      RoleArn: string;
      StreamArn: string;
    }
  }
  export interface ResponseHeadersPolicy {
    ResponseHeadersPolicyConfig: ResponseHeadersPolicy.ResponseHeadersPolicyConfig;
  }
  export namespace ResponseHeadersPolicy {
    export interface Attr {
      Id: string;
      LastModifiedTime: string;
    }
    export interface AccessControlAllowHeaders {
      Items: string[];
    }
    export interface AccessControlAllowMethods {
      Items: string[];
    }
    export interface AccessControlAllowOrigins {
      Items: string[];
    }
    export interface AccessControlExposeHeaders {
      Items: string[];
    }
    export interface ContentSecurityPolicy {
      ContentSecurityPolicy: string;
      Override: boolean;
    }
    export interface ContentTypeOptions {
      Override: boolean;
    }
    export interface CorsConfig {
      AccessControlAllowCredentials: boolean;
      AccessControlAllowHeaders: AccessControlAllowHeaders;
      AccessControlAllowMethods: AccessControlAllowMethods;
      AccessControlAllowOrigins: AccessControlAllowOrigins;
      AccessControlExposeHeaders?: AccessControlExposeHeaders;
      AccessControlMaxAgeSec?: number;
      OriginOverride: boolean;
    }
    export interface CustomHeader {
      Header: string;
      Override: boolean;
      Value: string;
    }
    export interface CustomHeadersConfig {
      Items: CustomHeader[];
    }
    export interface FrameOptions {
      FrameOption: string;
      Override: boolean;
    }
    export interface ReferrerPolicy {
      Override: boolean;
      ReferrerPolicy: string;
    }
    export interface RemoveHeader {
      Header: string;
    }
    export interface RemoveHeadersConfig {
      Items: RemoveHeader[];
    }
    export interface ResponseHeadersPolicyConfig {
      Comment?: string;
      CorsConfig?: CorsConfig;
      CustomHeadersConfig?: CustomHeadersConfig;
      Name: string;
      RemoveHeadersConfig?: RemoveHeadersConfig;
      SecurityHeadersConfig?: SecurityHeadersConfig;
      ServerTimingHeadersConfig?: ServerTimingHeadersConfig;
    }
    export interface SecurityHeadersConfig {
      ContentSecurityPolicy?: ContentSecurityPolicy;
      ContentTypeOptions?: ContentTypeOptions;
      FrameOptions?: FrameOptions;
      ReferrerPolicy?: ReferrerPolicy;
      StrictTransportSecurity?: StrictTransportSecurity;
      XSSProtection?: XSSProtection;
    }
    export interface ServerTimingHeadersConfig {
      Enabled: boolean;
      SamplingRate?: number;
    }
    export interface StrictTransportSecurity {
      AccessControlMaxAgeSec: number;
      IncludeSubdomains?: boolean;
      Override: boolean;
      Preload?: boolean;
    }
    export interface XSSProtection {
      ModeBlock?: boolean;
      Override: boolean;
      Protection: boolean;
      ReportUri?: string;
    }
  }
  export interface StreamingDistribution {
    StreamingDistributionConfig: StreamingDistribution.StreamingDistributionConfig;
    Tags: Tag[];
  }
  export namespace StreamingDistribution {
    export interface Attr {
      DomainName: string;
    }
    export interface Logging {
      Bucket: string;
      Enabled: boolean;
      Prefix: string;
    }
    export interface S3Origin {
      DomainName: string;
      OriginAccessIdentity: string;
    }
    export interface StreamingDistributionConfig {
      Aliases?: string[];
      Comment: string;
      Enabled: boolean;
      Logging?: Logging;
      PriceClass?: string;
      S3Origin: S3Origin;
      TrustedSigners: TrustedSigners;
    }
    export interface TrustedSigners {
      AwsAccountNumbers?: string[];
      Enabled: boolean;
    }
  }
}
export namespace CloudTrail {
  export interface EventDataStore {
    AdvancedEventSelectors?: EventDataStore.AdvancedEventSelector[];
    KmsKeyId?: string;
    MultiRegionEnabled?: boolean;
    Name?: string;
    OrganizationEnabled?: boolean;
    RetentionPeriod?: number;
    Tags?: Tag[];
    TerminationProtectionEnabled?: boolean;
  }
  export namespace EventDataStore {
    export interface Attr {
      CreatedTimestamp: string;
      EventDataStoreArn: string;
      Status: string;
      UpdatedTimestamp: string;
    }
    export interface AdvancedEventSelector {
      FieldSelectors: AdvancedFieldSelector[];
      Name?: string;
    }
    export interface AdvancedFieldSelector {
      EndsWith?: string[];
      Equals?: string[];
      Field: string;
      NotEndsWith?: string[];
      NotEquals?: string[];
      NotStartsWith?: string[];
      StartsWith?: string[];
    }
  }
  export interface Trail {
    CloudWatchLogsLogGroupArn?: string;
    CloudWatchLogsRoleArn?: string;
    EnableLogFileValidation?: boolean;
    EventSelectors?: Trail.EventSelector[];
    IncludeGlobalServiceEvents?: boolean;
    InsightSelectors?: Trail.InsightSelector[];
    IsLogging: boolean;
    IsMultiRegionTrail?: boolean;
    IsOrganizationTrail?: boolean;
    KMSKeyId?: string;
    S3BucketName: string;
    S3KeyPrefix?: string;
    SnsTopicName?: string;
    Tags?: Tag[];
    TrailName?: string;
  }
  export namespace Trail {
    export interface Attr {
      Arn: string;
      SnsTopicArn: string;
    }
    export interface DataResource {
      Type: string;
      Values?: string[];
    }
    export interface EventSelector {
      DataResources?: DataResource[];
      ExcludeManagementEventSources?: string[];
      IncludeManagementEvents?: boolean;
      ReadWriteType?: string;
    }
    export interface InsightSelector {
      InsightType?: string;
    }
  }
}
export namespace CloudWatch {
  export interface Alarm {
    ActionsEnabled?: boolean;
    AlarmActions?: string[];
    AlarmDescription?: string;
    AlarmName?: string;
    ComparisonOperator: string;
    DatapointsToAlarm?: number;
    Dimensions?: Alarm.Dimension[];
    EvaluateLowSampleCountPercentile?: string;
    EvaluationPeriods: number;
    ExtendedStatistic?: string;
    InsufficientDataActions?: string[];
    MetricName?: string;
    Metrics?: Alarm.MetricDataQuery[];
    Namespace?: string;
    OKActions?: string[];
    Period?: number;
    Statistic?: string;
    Threshold?: number;
    ThresholdMetricId?: string;
    TreatMissingData?: string;
    Unit?: string;
  }
  export namespace Alarm {
    export interface Attr {
      Arn: string;
    }
    export interface Dimension {
      Name: string;
      Value: string;
    }
    export interface Metric {
      Dimensions?: Dimension[];
      MetricName?: string;
      Namespace?: string;
    }
    export interface MetricDataQuery {
      AccountId?: string;
      Expression?: string;
      Id: string;
      Label?: string;
      MetricStat?: MetricStat;
      Period?: number;
      ReturnData?: boolean;
    }
    export interface MetricStat {
      Metric: Metric;
      Period: number;
      Stat: string;
      Unit?: string;
    }
  }
  export interface AnomalyDetector {
    Configuration?: AnomalyDetector.Configuration;
    Dimensions?: AnomalyDetector.Dimension[];
    MetricMathAnomalyDetector?: AnomalyDetector.MetricMathAnomalyDetector;
    MetricName?: string;
    Namespace?: string;
    SingleMetricAnomalyDetector?: AnomalyDetector.SingleMetricAnomalyDetector;
    Stat?: string;
  }
  export namespace AnomalyDetector {
    export interface Attr {}
    export interface Configuration {
      ExcludedTimeRanges?: Range[];
      MetricTimeZone?: string;
    }
    export interface Dimension {
      Name: string;
      Value: string;
    }
    export interface Metric {
      Dimensions?: Dimension[];
      MetricName: string;
      Namespace: string;
    }
    export interface MetricDataQueries {}
    export interface MetricDataQuery {
      AccountId?: string;
      Expression?: string;
      Id: string;
      Label?: string;
      MetricStat?: MetricStat;
      Period?: number;
      ReturnData?: boolean;
    }
    export interface MetricMathAnomalyDetector {
      MetricDataQueries?: MetricDataQuery[];
    }
    export interface MetricStat {
      Metric: Metric;
      Period: number;
      Stat: string;
      Unit?: string;
    }
    export interface Range {
      EndTime: string;
      StartTime: string;
    }
    export interface SingleMetricAnomalyDetector {
      Dimensions?: Dimension[];
      MetricName?: string;
      Namespace?: string;
      Stat?: string;
    }
  }
  export interface CompositeAlarm {
    ActionsEnabled?: boolean;
    ActionsSuppressor?: string;
    ActionsSuppressorExtensionPeriod?: number;
    ActionsSuppressorWaitPeriod?: number;
    AlarmActions?: string[];
    AlarmDescription?: string;
    AlarmName?: string;
    AlarmRule: string;
    InsufficientDataActions?: string[];
    OKActions?: string[];
  }
  export interface Dashboard {
    DashboardBody: string;
    DashboardName?: string;
  }
  export interface InsightRule {
    RuleBody: string;
    RuleName: string;
    RuleState: string;
    Tags?: InsightRule.Tags;
  }
  export namespace InsightRule {
    export interface Attr {
      Arn: string;
      RuleName: string;
    }
    export interface Tags {}
  }
  export interface MetricStream {
    ExcludeFilters?: MetricStream.MetricStreamFilter[];
    FirehoseArn: string;
    IncludeFilters?: MetricStream.MetricStreamFilter[];
    IncludeLinkedAccountsMetrics?: boolean;
    Name?: string;
    OutputFormat: string;
    RoleArn: string;
    StatisticsConfigurations?: MetricStream.MetricStreamStatisticsConfiguration[];
    Tags?: Tag[];
  }
  export namespace MetricStream {
    export interface Attr {
      Arn: string;
      CreationDate: string;
      LastUpdateDate: string;
      State: string;
    }
    export interface MetricStreamFilter {
      Namespace: string;
    }
    export interface MetricStreamStatisticsConfiguration {
      AdditionalStatistics: string[];
      IncludeMetrics: MetricStreamStatisticsMetric[];
    }
    export interface MetricStreamStatisticsMetric {
      MetricName: string;
      Namespace: string;
    }
  }
}
export namespace CodeArtifact {
  export interface Domain {
    DomainName: string;
    EncryptionKey?: string;
    PermissionsPolicyDocument?: any;
    Tags?: Tag[];
  }
  export interface Repository {
    Description?: string;
    DomainName: string;
    DomainOwner?: string;
    ExternalConnections?: string[];
    PermissionsPolicyDocument?: any;
    RepositoryName: string;
    Tags?: Tag[];
    Upstreams?: string[];
  }
}
export namespace CodeBuild {
  export interface Project {
    Artifacts: Project.Artifacts;
    BadgeEnabled?: boolean;
    BuildBatchConfig?: Project.ProjectBuildBatchConfig;
    Cache?: Project.ProjectCache;
    ConcurrentBuildLimit?: number;
    Description?: string;
    EncryptionKey?: string;
    Environment: Project.Environment;
    FileSystemLocations?: Project.ProjectFileSystemLocation[];
    LogsConfig?: Project.LogsConfig;
    Name?: string;
    QueuedTimeoutInMinutes?: number;
    ResourceAccessRole?: string;
    SecondaryArtifacts?: Project.Artifacts[];
    SecondarySourceVersions?: Project.ProjectSourceVersion[];
    SecondarySources?: Project.Source[];
    ServiceRole: string;
    Source: Project.Source;
    SourceVersion?: string;
    Tags?: Tag[];
    TimeoutInMinutes?: number;
    Triggers?: Project.ProjectTriggers;
    Visibility?: string;
    VpcConfig?: Project.VpcConfig;
  }
  export namespace Project {
    export interface Attr {
      Arn: string;
    }
    export interface Artifacts {
      ArtifactIdentifier?: string;
      EncryptionDisabled?: boolean;
      Location?: string;
      Name?: string;
      NamespaceType?: string;
      OverrideArtifactName?: boolean;
      Packaging?: string;
      Path?: string;
      Type: string;
    }
    export interface BatchRestrictions {
      ComputeTypesAllowed?: string[];
      MaximumBuildsAllowed?: number;
    }
    export interface BuildStatusConfig {
      Context?: string;
      TargetUrl?: string;
    }
    export interface CloudWatchLogsConfig {
      GroupName?: string;
      Status: string;
      StreamName?: string;
    }
    export interface Environment {
      Certificate?: string;
      ComputeType: string;
      EnvironmentVariables?: EnvironmentVariable[];
      Image: string;
      ImagePullCredentialsType?: string;
      PrivilegedMode?: boolean;
      RegistryCredential?: RegistryCredential;
      Type: string;
    }
    export interface EnvironmentVariable {
      Name: string;
      Type?: string;
      Value: string;
    }
    export interface FilterGroup {}
    export interface GitSubmodulesConfig {
      FetchSubmodules: boolean;
    }
    export interface LogsConfig {
      CloudWatchLogs?: CloudWatchLogsConfig;
      S3Logs?: S3LogsConfig;
    }
    export interface ProjectBuildBatchConfig {
      BatchReportMode?: string;
      CombineArtifacts?: boolean;
      Restrictions?: BatchRestrictions;
      ServiceRole?: string;
      TimeoutInMins?: number;
    }
    export interface ProjectCache {
      Location?: string;
      Modes?: string[];
      Type: string;
    }
    export interface ProjectFileSystemLocation {
      Identifier: string;
      Location: string;
      MountOptions?: string;
      MountPoint: string;
      Type: string;
    }
    export interface ProjectSourceVersion {
      SourceIdentifier: string;
      SourceVersion?: string;
    }
    export interface ProjectTriggers {
      BuildType?: string;
      FilterGroups?: FilterGroup[];
      Webhook?: boolean;
    }
    export interface RegistryCredential {
      Credential: string;
      CredentialProvider: string;
    }
    export interface S3LogsConfig {
      EncryptionDisabled?: boolean;
      Location?: string;
      Status: string;
    }
    export interface Source {
      Auth?: SourceAuth;
      BuildSpec?: string;
      BuildStatusConfig?: BuildStatusConfig;
      GitCloneDepth?: number;
      GitSubmodulesConfig?: GitSubmodulesConfig;
      InsecureSsl?: boolean;
      Location?: string;
      ReportBuildStatus?: boolean;
      SourceIdentifier?: string;
      Type: string;
    }
    export interface SourceAuth {
      Resource?: string;
      Type: string;
    }
    export interface VpcConfig {
      SecurityGroupIds?: string[];
      Subnets?: string[];
      VpcId?: string;
    }
    export interface WebhookFilter {
      ExcludeMatchedPattern?: boolean;
      Pattern: string;
      Type: string;
    }
  }
  export interface ReportGroup {
    DeleteReports?: boolean;
    ExportConfig: ReportGroup.ReportExportConfig;
    Name?: string;
    Tags?: Tag[];
    Type: string;
  }
  export namespace ReportGroup {
    export interface Attr {
      Arn: string;
    }
    export interface ReportExportConfig {
      ExportConfigType: string;
      S3Destination?: S3ReportExportConfig;
    }
    export interface S3ReportExportConfig {
      Bucket: string;
      BucketOwner?: string;
      EncryptionDisabled?: boolean;
      EncryptionKey?: string;
      Packaging?: string;
      Path?: string;
    }
  }
  export interface SourceCredential {
    AuthType: string;
    ServerType: string;
    Token: string;
    Username?: string;
  }
}
export namespace CodeCommit {
  export interface Repository {
    Code?: Repository.Code;
    RepositoryDescription?: string;
    RepositoryName: string;
    Tags?: Tag[];
    Triggers?: Repository.RepositoryTrigger[];
  }
  export namespace Repository {
    export interface Attr {
      Arn: string;
      CloneUrlHttp: string;
      CloneUrlSsh: string;
      Name: string;
    }
    export interface Code {
      BranchName?: string;
      S3: S3;
    }
    export interface RepositoryTrigger {
      Branches?: string[];
      CustomData?: string;
      DestinationArn: string;
      Events: string[];
      Name: string;
    }
    export interface S3 {
      Bucket: string;
      Key: string;
      ObjectVersion?: string;
    }
  }
}
export namespace CodeDeploy {
  export interface Application {
    ApplicationName?: string;
    ComputePlatform?: string;
    Tags?: Tag[];
  }
  export interface DeploymentConfig {
    ComputePlatform?: string;
    DeploymentConfigName?: string;
    MinimumHealthyHosts?: DeploymentConfig.MinimumHealthyHosts;
    TrafficRoutingConfig?: DeploymentConfig.TrafficRoutingConfig;
  }
  export namespace DeploymentConfig {
    export interface Attr {}
    export interface MinimumHealthyHosts {
      Type: string;
      Value: number;
    }
    export interface TimeBasedCanary {
      CanaryInterval: number;
      CanaryPercentage: number;
    }
    export interface TimeBasedLinear {
      LinearInterval: number;
      LinearPercentage: number;
    }
    export interface TrafficRoutingConfig {
      TimeBasedCanary?: TimeBasedCanary;
      TimeBasedLinear?: TimeBasedLinear;
      Type: string;
    }
  }
  export interface DeploymentGroup {
    AlarmConfiguration?: DeploymentGroup.AlarmConfiguration;
    ApplicationName: string;
    AutoRollbackConfiguration?: DeploymentGroup.AutoRollbackConfiguration;
    AutoScalingGroups?: string[];
    BlueGreenDeploymentConfiguration?: DeploymentGroup.BlueGreenDeploymentConfiguration;
    Deployment?: DeploymentGroup.Deployment;
    DeploymentConfigName?: string;
    DeploymentGroupName?: string;
    DeploymentStyle?: DeploymentGroup.DeploymentStyle;
    ECSServices?: DeploymentGroup.ECSService[];
    Ec2TagFilters?: DeploymentGroup.EC2TagFilter[];
    Ec2TagSet?: DeploymentGroup.EC2TagSet;
    LoadBalancerInfo?: DeploymentGroup.LoadBalancerInfo;
    OnPremisesInstanceTagFilters?: DeploymentGroup.TagFilter[];
    OnPremisesTagSet?: DeploymentGroup.OnPremisesTagSet;
    OutdatedInstancesStrategy?: string;
    ServiceRoleArn: string;
    Tags?: Tag[];
    TriggerConfigurations?: DeploymentGroup.TriggerConfig[];
  }
  export namespace DeploymentGroup {
    export interface Attr {}
    export interface Alarm {
      Name?: string;
    }
    export interface AlarmConfiguration {
      Alarms?: Alarm[];
      Enabled?: boolean;
      IgnorePollAlarmFailure?: boolean;
    }
    export interface AutoRollbackConfiguration {
      Enabled?: boolean;
      Events?: string[];
    }
    export interface BlueGreenDeploymentConfiguration {
      DeploymentReadyOption?: DeploymentReadyOption;
      GreenFleetProvisioningOption?: GreenFleetProvisioningOption;
      TerminateBlueInstancesOnDeploymentSuccess?: BlueInstanceTerminationOption;
    }
    export interface BlueInstanceTerminationOption {
      Action?: string;
      TerminationWaitTimeInMinutes?: number;
    }
    export interface Deployment {
      Description?: string;
      IgnoreApplicationStopFailures?: boolean;
      Revision: RevisionLocation;
    }
    export interface DeploymentReadyOption {
      ActionOnTimeout?: string;
      WaitTimeInMinutes?: number;
    }
    export interface DeploymentStyle {
      DeploymentOption?: string;
      DeploymentType?: string;
    }
    export interface EC2TagFilter {
      Key?: string;
      Type?: string;
      Value?: string;
    }
    export interface EC2TagSet {
      Ec2TagSetList?: EC2TagSetListObject[];
    }
    export interface EC2TagSetListObject {
      Ec2TagGroup?: EC2TagFilter[];
    }
    export interface ECSService {
      ClusterName: string;
      ServiceName: string;
    }
    export interface ELBInfo {
      Name?: string;
    }
    export interface GitHubLocation {
      CommitId: string;
      Repository: string;
    }
    export interface GreenFleetProvisioningOption {
      Action?: string;
    }
    export interface LoadBalancerInfo {
      ElbInfoList?: ELBInfo[];
      TargetGroupInfoList?: TargetGroupInfo[];
      TargetGroupPairInfoList?: TargetGroupPairInfo[];
    }
    export interface OnPremisesTagSet {
      OnPremisesTagSetList?: OnPremisesTagSetListObject[];
    }
    export interface OnPremisesTagSetListObject {
      OnPremisesTagGroup?: TagFilter[];
    }
    export interface RevisionLocation {
      GitHubLocation?: GitHubLocation;
      RevisionType?: string;
      S3Location?: S3Location;
    }
    export interface S3Location {
      Bucket: string;
      BundleType?: string;
      ETag?: string;
      Key: string;
      Version?: string;
    }
    export interface TagFilter {
      Key?: string;
      Type?: string;
      Value?: string;
    }
    export interface TargetGroupInfo {
      Name?: string;
    }
    export interface TargetGroupPairInfo {
      ProdTrafficRoute?: TrafficRoute;
      TargetGroups?: TargetGroupInfo[];
      TestTrafficRoute?: TrafficRoute;
    }
    export interface TrafficRoute {
      ListenerArns?: string[];
    }
    export interface TriggerConfig {
      TriggerEvents?: string[];
      TriggerName?: string;
      TriggerTargetArn?: string;
    }
  }
}
export namespace CodeGuruProfiler {
  export interface ProfilingGroup {
    AgentPermissions?: any;
    AnomalyDetectionNotificationConfiguration?: ProfilingGroup.Channel[];
    ComputePlatform?: string;
    ProfilingGroupName: string;
    Tags?: Tag[];
  }
  export namespace ProfilingGroup {
    export interface Attr {
      Arn: string;
    }
    export interface AgentPermissions {
      Principals: string[];
    }
    export interface Channel {
      channelId?: string;
      channelUri: string;
    }
  }
}
export namespace CodeGuruReviewer {
  export interface RepositoryAssociation {
    BucketName?: string;
    ConnectionArn?: string;
    Name: string;
    Owner?: string;
    Tags?: Tag[];
    Type: string;
  }
}
export namespace CodePipeline {
  export interface CustomActionType {
    Category: string;
    ConfigurationProperties?: CustomActionType.ConfigurationProperties[];
    InputArtifactDetails: CustomActionType.ArtifactDetails;
    OutputArtifactDetails: CustomActionType.ArtifactDetails;
    Provider: string;
    Settings?: CustomActionType.Settings;
    Tags?: Tag[];
    Version: string;
  }
  export namespace CustomActionType {
    export interface Attr {
      Id: string;
    }
    export interface ArtifactDetails {
      MaximumCount: number;
      MinimumCount: number;
    }
    export interface ConfigurationProperties {
      Description?: string;
      Key: boolean;
      Name: string;
      Queryable?: boolean;
      Required: boolean;
      Secret: boolean;
      Type?: string;
    }
    export interface Settings {
      EntityUrlTemplate?: string;
      ExecutionUrlTemplate?: string;
      RevisionUrlTemplate?: string;
      ThirdPartyConfigurationUrl?: string;
    }
  }
  export interface Pipeline {
    ArtifactStore?: Pipeline.ArtifactStore;
    ArtifactStores?: Pipeline.ArtifactStoreMap[];
    DisableInboundStageTransitions?: Pipeline.StageTransition[];
    Name?: string;
    RestartExecutionOnUpdate?: boolean;
    RoleArn: string;
    Stages: Pipeline.StageDeclaration[];
    Tags?: Tag[];
  }
  export namespace Pipeline {
    export interface Attr {
      Version: string;
    }
    export interface ActionDeclaration {
      ActionTypeId: ActionTypeId;
      Configuration?: any;
      InputArtifacts?: InputArtifact[];
      Name: string;
      Namespace?: string;
      OutputArtifacts?: OutputArtifact[];
      Region?: string;
      RoleArn?: string;
      RunOrder?: number;
    }
    export interface ActionTypeId {
      Category: string;
      Owner: string;
      Provider: string;
      Version: string;
    }
    export interface ArtifactStore {
      EncryptionKey?: EncryptionKey;
      Location: string;
      Type: string;
    }
    export interface ArtifactStoreMap {
      ArtifactStore: ArtifactStore;
      Region: string;
    }
    export interface BlockerDeclaration {
      Name: string;
      Type: string;
    }
    export interface EncryptionKey {
      Id: string;
      Type: string;
    }
    export interface InputArtifact {
      Name: string;
    }
    export interface OutputArtifact {
      Name: string;
    }
    export interface StageDeclaration {
      Actions: ActionDeclaration[];
      Blockers?: BlockerDeclaration[];
      Name: string;
    }
    export interface StageTransition {
      Reason: string;
      StageName: string;
    }
  }
  export interface Webhook {
    Authentication: string;
    AuthenticationConfiguration: Webhook.WebhookAuthConfiguration;
    Filters: Webhook.WebhookFilterRule[];
    Name?: string;
    RegisterWithThirdParty?: boolean;
    TargetAction: string;
    TargetPipeline: string;
    TargetPipelineVersion: number;
  }
  export namespace Webhook {
    export interface Attr {
      Url: string;
    }
    export interface WebhookAuthConfiguration {
      AllowedIPRange?: string;
      SecretToken?: string;
    }
    export interface WebhookFilterRule {
      JsonPath: string;
      MatchEquals?: string;
    }
  }
}
export namespace CodeStar {
  export interface GitHubRepository {
    Code?: GitHubRepository.Code;
    ConnectionArn?: string;
    EnableIssues?: boolean;
    IsPrivate?: boolean;
    RepositoryAccessToken?: string;
    RepositoryDescription?: string;
    RepositoryName: string;
    RepositoryOwner: string;
  }
  export namespace GitHubRepository {
    export interface Attr {}
    export interface Code {
      S3: S3;
    }
    export interface S3 {
      Bucket: string;
      Key: string;
      ObjectVersion?: string;
    }
  }
}
export namespace CodeStarConnections {
  export interface Connection {
    ConnectionName: string;
    HostArn?: string;
    ProviderType?: string;
    Tags?: Tag[];
  }
}
export namespace CodeStarNotifications {
  export interface NotificationRule {
    CreatedBy?: string;
    DetailType: string;
    EventTypeId?: string;
    EventTypeIds: string[];
    Name: string;
    Resource: string;
    Status?: string;
    Tags?: any;
    TargetAddress?: string;
    Targets: NotificationRule.Target[];
  }
  export namespace NotificationRule {
    export interface Attr {
      Arn: string;
    }
    export interface Target {
      TargetAddress: string;
      TargetType: string;
    }
  }
}
export namespace Cognito {
  export interface IdentityPool {
    AllowClassicFlow?: boolean;
    AllowUnauthenticatedIdentities: boolean;
    CognitoEvents?: any;
    CognitoIdentityProviders?: IdentityPool.CognitoIdentityProvider[];
    CognitoStreams?: IdentityPool.CognitoStreams;
    DeveloperProviderName?: string;
    IdentityPoolName?: string;
    OpenIdConnectProviderARNs?: string[];
    PushSync?: IdentityPool.PushSync;
    SamlProviderARNs?: string[];
    SupportedLoginProviders?: any;
  }
  export namespace IdentityPool {
    export interface Attr {
      Name: string;
    }
    export interface CognitoIdentityProvider {
      ClientId?: string;
      ProviderName?: string;
      ServerSideTokenCheck?: boolean;
    }
    export interface CognitoStreams {
      RoleArn?: string;
      StreamName?: string;
      StreamingStatus?: string;
    }
    export interface PushSync {
      ApplicationArns?: string[];
      RoleArn?: string;
    }
  }
  export interface IdentityPoolRoleAttachment {
    IdentityPoolId: string;
    RoleMappings?: Record<string, IdentityPoolRoleAttachment.RoleMapping>;
    Roles?: any;
  }
  export namespace IdentityPoolRoleAttachment {
    export interface Attr {}
    export interface MappingRule {
      Claim: string;
      MatchType: string;
      RoleARN: string;
      Value: string;
    }
    export interface RoleMapping {
      AmbiguousRoleResolution?: string;
      IdentityProvider?: string;
      RulesConfiguration?: RulesConfigurationType;
      Type: string;
    }
    export interface RulesConfigurationType {
      Rules: MappingRule[];
    }
  }
  export interface UserPool {
    AccountRecoverySetting?: UserPool.AccountRecoverySetting;
    AdminCreateUserConfig?: UserPool.AdminCreateUserConfig;
    AliasAttributes?: string[];
    AutoVerifiedAttributes?: string[];
    DeletionProtection?: string;
    DeviceConfiguration?: UserPool.DeviceConfiguration;
    EmailConfiguration?: UserPool.EmailConfiguration;
    EmailVerificationMessage?: string;
    EmailVerificationSubject?: string;
    EnabledMfas?: string[];
    LambdaConfig?: UserPool.LambdaConfig;
    MfaConfiguration?: string;
    Policies?: UserPool.Policies;
    Schema?: UserPool.SchemaAttribute[];
    SmsAuthenticationMessage?: string;
    SmsConfiguration?: UserPool.SmsConfiguration;
    SmsVerificationMessage?: string;
    UserAttributeUpdateSettings?: UserPool.UserAttributeUpdateSettings;
    UserPoolAddOns?: UserPool.UserPoolAddOns;
    UserPoolName?: string;
    UserPoolTags?: any;
    UsernameAttributes?: string[];
    UsernameConfiguration?: UserPool.UsernameConfiguration;
    VerificationMessageTemplate?: UserPool.VerificationMessageTemplate;
  }
  export namespace UserPool {
    export interface Attr {
      Arn: string;
      ProviderName: string;
      ProviderURL: string;
    }
    export interface AccountRecoverySetting {
      RecoveryMechanisms?: RecoveryOption[];
    }
    export interface AdminCreateUserConfig {
      AllowAdminCreateUserOnly?: boolean;
      InviteMessageTemplate?: InviteMessageTemplate;
      UnusedAccountValidityDays?: number;
    }
    export interface CustomEmailSender {
      LambdaArn?: string;
      LambdaVersion?: string;
    }
    export interface CustomSMSSender {
      LambdaArn?: string;
      LambdaVersion?: string;
    }
    export interface DeviceConfiguration {
      ChallengeRequiredOnNewDevice?: boolean;
      DeviceOnlyRememberedOnUserPrompt?: boolean;
    }
    export interface EmailConfiguration {
      ConfigurationSet?: string;
      EmailSendingAccount?: string;
      From?: string;
      ReplyToEmailAddress?: string;
      SourceArn?: string;
    }
    export interface InviteMessageTemplate {
      EmailMessage?: string;
      EmailSubject?: string;
      SMSMessage?: string;
    }
    export interface LambdaConfig {
      CreateAuthChallenge?: string;
      CustomEmailSender?: CustomEmailSender;
      CustomMessage?: string;
      CustomSMSSender?: CustomSMSSender;
      DefineAuthChallenge?: string;
      KMSKeyID?: string;
      PostAuthentication?: string;
      PostConfirmation?: string;
      PreAuthentication?: string;
      PreSignUp?: string;
      PreTokenGeneration?: string;
      UserMigration?: string;
      VerifyAuthChallengeResponse?: string;
    }
    export interface NumberAttributeConstraints {
      MaxValue?: string;
      MinValue?: string;
    }
    export interface PasswordPolicy {
      MinimumLength?: number;
      RequireLowercase?: boolean;
      RequireNumbers?: boolean;
      RequireSymbols?: boolean;
      RequireUppercase?: boolean;
      TemporaryPasswordValidityDays?: number;
    }
    export interface Policies {
      PasswordPolicy?: PasswordPolicy;
    }
    export interface RecoveryOption {
      Name?: string;
      Priority?: number;
    }
    export interface SchemaAttribute {
      AttributeDataType?: string;
      DeveloperOnlyAttribute?: boolean;
      Mutable?: boolean;
      Name?: string;
      NumberAttributeConstraints?: NumberAttributeConstraints;
      Required?: boolean;
      StringAttributeConstraints?: StringAttributeConstraints;
    }
    export interface SmsConfiguration {
      ExternalId?: string;
      SnsCallerArn?: string;
      SnsRegion?: string;
    }
    export interface StringAttributeConstraints {
      MaxLength?: string;
      MinLength?: string;
    }
    export interface UserAttributeUpdateSettings {
      AttributesRequireVerificationBeforeUpdate: string[];
    }
    export interface UserPoolAddOns {
      AdvancedSecurityMode?: string;
    }
    export interface UsernameConfiguration {
      CaseSensitive?: boolean;
    }
    export interface VerificationMessageTemplate {
      DefaultEmailOption?: string;
      EmailMessage?: string;
      EmailMessageByLink?: string;
      EmailSubject?: string;
      EmailSubjectByLink?: string;
      SmsMessage?: string;
    }
  }
  export interface UserPoolClient {
    AccessTokenValidity?: number;
    AllowedOAuthFlows?: string[];
    AllowedOAuthFlowsUserPoolClient?: boolean;
    AllowedOAuthScopes?: string[];
    AnalyticsConfiguration?: UserPoolClient.AnalyticsConfiguration;
    AuthSessionValidity?: number;
    CallbackURLs?: string[];
    ClientName?: string;
    DefaultRedirectURI?: string;
    EnablePropagateAdditionalUserContextData?: boolean;
    EnableTokenRevocation?: boolean;
    ExplicitAuthFlows?: string[];
    GenerateSecret?: boolean;
    IdTokenValidity?: number;
    LogoutURLs?: string[];
    PreventUserExistenceErrors?: string;
    ReadAttributes?: string[];
    RefreshTokenValidity?: number;
    SupportedIdentityProviders?: string[];
    TokenValidityUnits?: UserPoolClient.TokenValidityUnits;
    UserPoolId: string;
    WriteAttributes?: string[];
  }
  export namespace UserPoolClient {
    export interface Attr {
      ClientSecret: string;
      Name: string;
    }
    export interface AnalyticsConfiguration {
      ApplicationArn?: string;
      ApplicationId?: string;
      ExternalId?: string;
      RoleArn?: string;
      UserDataShared?: boolean;
    }
    export interface TokenValidityUnits {
      AccessToken?: string;
      IdToken?: string;
      RefreshToken?: string;
    }
  }
  export interface UserPoolDomain {
    CustomDomainConfig?: UserPoolDomain.CustomDomainConfigType;
    Domain: string;
    UserPoolId: string;
  }
  export namespace UserPoolDomain {
    export interface Attr {
      CloudFrontDistribution: string;
    }
    export interface CustomDomainConfigType {
      CertificateArn?: string;
    }
  }
  export interface UserPoolGroup {
    Description?: string;
    GroupName?: string;
    Precedence?: number;
    RoleArn?: string;
    UserPoolId: string;
  }
  export interface UserPoolIdentityProvider {
    AttributeMapping?: any;
    IdpIdentifiers?: string[];
    ProviderDetails?: any;
    ProviderName: string;
    ProviderType: string;
    UserPoolId: string;
  }
  export interface UserPoolResourceServer {
    Identifier: string;
    Name: string;
    Scopes?: UserPoolResourceServer.ResourceServerScopeType[];
    UserPoolId: string;
  }
  export namespace UserPoolResourceServer {
    export interface Attr {}
    export interface ResourceServerScopeType {
      ScopeDescription: string;
      ScopeName: string;
    }
  }
  export interface UserPoolRiskConfigurationAttachment {
    AccountTakeoverRiskConfiguration?: UserPoolRiskConfigurationAttachment.AccountTakeoverRiskConfigurationType;
    ClientId: string;
    CompromisedCredentialsRiskConfiguration?: UserPoolRiskConfigurationAttachment.CompromisedCredentialsRiskConfigurationType;
    RiskExceptionConfiguration?: UserPoolRiskConfigurationAttachment.RiskExceptionConfigurationType;
    UserPoolId: string;
  }
  export namespace UserPoolRiskConfigurationAttachment {
    export interface Attr {}
    export interface AccountTakeoverActionType {
      EventAction: string;
      Notify: boolean;
    }
    export interface AccountTakeoverActionsType {
      HighAction?: AccountTakeoverActionType;
      LowAction?: AccountTakeoverActionType;
      MediumAction?: AccountTakeoverActionType;
    }
    export interface AccountTakeoverRiskConfigurationType {
      Actions: AccountTakeoverActionsType;
      NotifyConfiguration?: NotifyConfigurationType;
    }
    export interface CompromisedCredentialsActionsType {
      EventAction: string;
    }
    export interface CompromisedCredentialsRiskConfigurationType {
      Actions: CompromisedCredentialsActionsType;
      EventFilter?: string[];
    }
    export interface NotifyConfigurationType {
      BlockEmail?: NotifyEmailType;
      From?: string;
      MfaEmail?: NotifyEmailType;
      NoActionEmail?: NotifyEmailType;
      ReplyTo?: string;
      SourceArn: string;
    }
    export interface NotifyEmailType {
      HtmlBody?: string;
      Subject: string;
      TextBody?: string;
    }
    export interface RiskExceptionConfigurationType {
      BlockedIPRangeList?: string[];
      SkippedIPRangeList?: string[];
    }
  }
  export interface UserPoolUICustomizationAttachment {
    CSS?: string;
    ClientId: string;
    UserPoolId: string;
  }
  export interface UserPoolUser {
    ClientMetadata?: any;
    DesiredDeliveryMediums?: string[];
    ForceAliasCreation?: boolean;
    MessageAction?: string;
    UserAttributes?: UserPoolUser.AttributeType[];
    UserPoolId: string;
    Username?: string;
    ValidationData?: UserPoolUser.AttributeType[];
  }
  export namespace UserPoolUser {
    export interface Attr {}
    export interface AttributeType {
      Name?: string;
      Value?: string;
    }
  }
  export interface UserPoolUserToGroupAttachment {
    GroupName: string;
    UserPoolId: string;
    Username: string;
  }
}
export namespace Config {
  export interface AggregationAuthorization {
    AuthorizedAccountId: string;
    AuthorizedAwsRegion: string;
    Tags?: Tag[];
  }
  export interface ConfigRule {
    ConfigRuleName?: string;
    Description?: string;
    InputParameters?: any;
    MaximumExecutionFrequency?: string;
    Scope?: ConfigRule.Scope;
    Source: ConfigRule.Source;
  }
  export namespace ConfigRule {
    export interface Attr {
      Arn: string;
      "Compliance.Type": string;
      ConfigRuleId: string;
    }
    export interface CustomPolicyDetails {
      EnableDebugLogDelivery?: boolean;
      PolicyRuntime?: string;
      PolicyText?: string;
    }
    export interface Scope {
      ComplianceResourceId?: string;
      ComplianceResourceTypes?: string[];
      TagKey?: string;
      TagValue?: string;
    }
    export interface Source {
      CustomPolicyDetails?: CustomPolicyDetails;
      Owner: string;
      SourceDetails?: SourceDetail[];
      SourceIdentifier?: string;
    }
    export interface SourceDetail {
      EventSource: string;
      MaximumExecutionFrequency?: string;
      MessageType: string;
    }
  }
  export interface ConfigurationAggregator {
    AccountAggregationSources?: ConfigurationAggregator.AccountAggregationSource[];
    ConfigurationAggregatorName?: string;
    OrganizationAggregationSource?: ConfigurationAggregator.OrganizationAggregationSource;
    Tags?: Tag[];
  }
  export namespace ConfigurationAggregator {
    export interface Attr {
      ConfigurationAggregatorArn: string;
    }
    export interface AccountAggregationSource {
      AccountIds: string[];
      AllAwsRegions?: boolean;
      AwsRegions?: string[];
    }
    export interface OrganizationAggregationSource {
      AllAwsRegions?: boolean;
      AwsRegions?: string[];
      RoleArn: string;
    }
  }
  export interface ConfigurationRecorder {
    Name?: string;
    RecordingGroup?: ConfigurationRecorder.RecordingGroup;
    RoleARN: string;
  }
  export namespace ConfigurationRecorder {
    export interface Attr {}
    export interface RecordingGroup {
      AllSupported?: boolean;
      IncludeGlobalResourceTypes?: boolean;
      ResourceTypes?: string[];
    }
  }
  export interface ConformancePack {
    ConformancePackInputParameters?: ConformancePack.ConformancePackInputParameter[];
    ConformancePackName: string;
    DeliveryS3Bucket?: string;
    DeliveryS3KeyPrefix?: string;
    TemplateBody?: string;
    TemplateS3Uri?: string;
    TemplateSSMDocumentDetails?: any;
  }
  export namespace ConformancePack {
    export interface Attr {}
    export interface ConformancePackInputParameter {
      ParameterName: string;
      ParameterValue: string;
    }
    export interface TemplateSSMDocumentDetails {
      DocumentName?: string;
      DocumentVersion?: string;
    }
  }
  export interface DeliveryChannel {
    ConfigSnapshotDeliveryProperties?: DeliveryChannel.ConfigSnapshotDeliveryProperties;
    Name?: string;
    S3BucketName: string;
    S3KeyPrefix?: string;
    S3KmsKeyArn?: string;
    SnsTopicARN?: string;
  }
  export namespace DeliveryChannel {
    export interface Attr {}
    export interface ConfigSnapshotDeliveryProperties {
      DeliveryFrequency?: string;
    }
  }
  export interface OrganizationConfigRule {
    ExcludedAccounts?: string[];
    OrganizationConfigRuleName: string;
    OrganizationCustomCodeRuleMetadata?: OrganizationConfigRule.OrganizationCustomCodeRuleMetadata;
    OrganizationCustomRuleMetadata?: OrganizationConfigRule.OrganizationCustomRuleMetadata;
    OrganizationManagedRuleMetadata?: OrganizationConfigRule.OrganizationManagedRuleMetadata;
  }
  export namespace OrganizationConfigRule {
    export interface Attr {}
    export interface OrganizationCustomCodeRuleMetadata {
      CodeText: string;
      DebugLogDeliveryAccounts?: string[];
      Description?: string;
      InputParameters?: string;
      MaximumExecutionFrequency?: string;
      OrganizationConfigRuleTriggerTypes?: string[];
      ResourceIdScope?: string;
      ResourceTypesScope?: string[];
      Runtime: string;
      TagKeyScope?: string;
      TagValueScope?: string;
    }
    export interface OrganizationCustomRuleMetadata {
      Description?: string;
      InputParameters?: string;
      LambdaFunctionArn: string;
      MaximumExecutionFrequency?: string;
      OrganizationConfigRuleTriggerTypes: string[];
      ResourceIdScope?: string;
      ResourceTypesScope?: string[];
      TagKeyScope?: string;
      TagValueScope?: string;
    }
    export interface OrganizationManagedRuleMetadata {
      Description?: string;
      InputParameters?: string;
      MaximumExecutionFrequency?: string;
      ResourceIdScope?: string;
      ResourceTypesScope?: string[];
      RuleIdentifier: string;
      TagKeyScope?: string;
      TagValueScope?: string;
    }
  }
  export interface OrganizationConformancePack {
    ConformancePackInputParameters?: OrganizationConformancePack.ConformancePackInputParameter[];
    DeliveryS3Bucket?: string;
    DeliveryS3KeyPrefix?: string;
    ExcludedAccounts?: string[];
    OrganizationConformancePackName: string;
    TemplateBody?: string;
    TemplateS3Uri?: string;
  }
  export namespace OrganizationConformancePack {
    export interface Attr {}
    export interface ConformancePackInputParameter {
      ParameterName: string;
      ParameterValue: string;
    }
  }
  export interface RemediationConfiguration {
    Automatic?: boolean;
    ConfigRuleName: string;
    ExecutionControls?: RemediationConfiguration.ExecutionControls;
    MaximumAutomaticAttempts?: number;
    Parameters?: any;
    ResourceType?: string;
    RetryAttemptSeconds?: number;
    TargetId: string;
    TargetType: string;
    TargetVersion?: string;
  }
  export namespace RemediationConfiguration {
    export interface Attr {}
    export interface ExecutionControls {
      SsmControls?: SsmControls;
    }
    export interface RemediationParameterValue {
      ResourceValue?: ResourceValue;
      StaticValue?: StaticValue;
    }
    export interface ResourceValue {
      Value?: string;
    }
    export interface SsmControls {
      ConcurrentExecutionRatePercentage?: number;
      ErrorPercentage?: number;
    }
    export interface StaticValue {
      Values?: string[];
    }
  }
  export interface StoredQuery {
    QueryDescription?: string;
    QueryExpression: string;
    QueryName: string;
    Tags?: Tag[];
  }
}
export namespace Connect {
  export interface ContactFlow {
    Content: string;
    Description?: string;
    InstanceArn: string;
    Name: string;
    State?: string;
    Tags?: Tag[];
    Type: string;
  }
  export interface ContactFlowModule {
    Content: string;
    Description?: string;
    InstanceArn: string;
    Name: string;
    State?: string;
    Tags?: Tag[];
  }
  export interface HoursOfOperation {
    Config: HoursOfOperation.HoursOfOperationConfig[];
    Description?: string;
    InstanceArn: string;
    Name: string;
    Tags?: Tag[];
    TimeZone: string;
  }
  export namespace HoursOfOperation {
    export interface Attr {
      HoursOfOperationArn: string;
    }
    export interface HoursOfOperationConfig {
      Day: string;
      EndTime: HoursOfOperationTimeSlice;
      StartTime: HoursOfOperationTimeSlice;
    }
    export interface HoursOfOperationTimeSlice {
      Hours: number;
      Minutes: number;
    }
  }
  export interface Instance {
    Attributes: Instance.Attributes;
    DirectoryId?: string;
    IdentityManagementType: string;
    InstanceAlias?: string;
  }
  export namespace Instance {
    export interface Attr {
      Arn: string;
      CreatedTime: string;
      Id: string;
      InstanceStatus: string;
      ServiceRole: string;
    }
    export interface Attributes {
      AutoResolveBestVoices?: boolean;
      ContactLens?: boolean;
      ContactflowLogs?: boolean;
      EarlyMedia?: boolean;
      InboundCalls: boolean;
      OutboundCalls: boolean;
      UseCustomTTSVoices?: boolean;
    }
  }
  export interface InstanceStorageConfig {
    InstanceArn: string;
    KinesisFirehoseConfig?: InstanceStorageConfig.KinesisFirehoseConfig;
    KinesisStreamConfig?: InstanceStorageConfig.KinesisStreamConfig;
    KinesisVideoStreamConfig?: InstanceStorageConfig.KinesisVideoStreamConfig;
    ResourceType: string;
    S3Config?: InstanceStorageConfig.S3Config;
    StorageType: string;
  }
  export namespace InstanceStorageConfig {
    export interface Attr {
      AssociationId: string;
    }
    export interface EncryptionConfig {
      EncryptionType: string;
      KeyId: string;
    }
    export interface KinesisFirehoseConfig {
      FirehoseArn: string;
    }
    export interface KinesisStreamConfig {
      StreamArn: string;
    }
    export interface KinesisVideoStreamConfig {
      EncryptionConfig?: EncryptionConfig;
      Prefix: string;
      RetentionPeriodHours: number;
    }
    export interface S3Config {
      BucketName: string;
      BucketPrefix: string;
      EncryptionConfig?: EncryptionConfig;
    }
  }
  export interface PhoneNumber {
    CountryCode: string;
    Description?: string;
    Prefix?: string;
    Tags?: Tag[];
    TargetArn: string;
    Type: string;
  }
  export interface QuickConnect {
    Description?: string;
    InstanceArn: string;
    Name: string;
    QuickConnectConfig: QuickConnect.QuickConnectConfig;
    Tags?: Tag[];
  }
  export namespace QuickConnect {
    export interface Attr {
      QuickConnectArn: string;
    }
    export interface PhoneNumberQuickConnectConfig {
      PhoneNumber: string;
    }
    export interface QueueQuickConnectConfig {
      ContactFlowArn: string;
      QueueArn: string;
    }
    export interface QuickConnectConfig {
      PhoneConfig?: PhoneNumberQuickConnectConfig;
      QueueConfig?: QueueQuickConnectConfig;
      QuickConnectType: string;
      UserConfig?: UserQuickConnectConfig;
    }
    export interface UserQuickConnectConfig {
      ContactFlowArn: string;
      UserArn: string;
    }
  }
  export interface Rule {
    Actions: Rule.Actions;
    Function: string;
    InstanceArn: string;
    Name: string;
    PublishStatus: string;
    Tags?: Tag[];
    TriggerEventSource: Rule.RuleTriggerEventSource;
  }
  export namespace Rule {
    export interface Attr {
      RuleArn: string;
    }
    export interface Actions {
      AssignContactCategoryActions?: any[];
      EventBridgeActions?: EventBridgeAction[];
      SendNotificationActions?: SendNotificationAction[];
      TaskActions?: TaskAction[];
    }
    export interface EventBridgeAction {
      Name: string;
    }
    export interface NotificationRecipientType {
      UserArns?: string[];
      UserTags?: Record<string, string>;
    }
    export interface Reference {
      Type: string;
      Value: string;
    }
    export interface RuleTriggerEventSource {
      EventSourceName: string;
      IntegrationAssociationArn?: string;
    }
    export interface SendNotificationAction {
      Content: string;
      ContentType: string;
      DeliveryMethod: string;
      Recipient: NotificationRecipientType;
      Subject?: string;
    }
    export interface TaskAction {
      ContactFlowArn: string;
      Description?: string;
      Name: string;
      References?: Record<string, Reference>;
    }
  }
  export interface TaskTemplate {
    ClientToken?: string;
    Constraints?: any;
    ContactFlowArn?: string;
    Defaults?: TaskTemplate.DefaultFieldValue[];
    Description?: string;
    Fields?: TaskTemplate.Field[];
    InstanceArn: string;
    Name?: string;
    Status?: string;
    Tags?: Tag[];
  }
  export namespace TaskTemplate {
    export interface Attr {
      Arn: string;
    }
    export interface Constraints {
      InvisibleFields?: InvisibleFieldInfo[];
      ReadOnlyFields?: ReadOnlyFieldInfo[];
      RequiredFields?: RequiredFieldInfo[];
    }
    export interface DefaultFieldValue {
      DefaultValue: string;
      Id: FieldIdentifier;
    }
    export interface Field {
      Description?: string;
      Id: FieldIdentifier;
      SingleSelectOptions?: string[];
      Type: string;
    }
    export interface FieldIdentifier {
      Name: string;
    }
    export interface InvisibleFieldInfo {
      Id: FieldIdentifier;
    }
    export interface ReadOnlyFieldInfo {
      Id: FieldIdentifier;
    }
    export interface RequiredFieldInfo {
      Id: FieldIdentifier;
    }
  }
  export interface User {
    DirectoryUserId?: string;
    HierarchyGroupArn?: string;
    IdentityInfo?: User.UserIdentityInfo;
    InstanceArn: string;
    Password?: string;
    PhoneConfig: User.UserPhoneConfig;
    RoutingProfileArn: string;
    SecurityProfileArns: string[];
    Tags?: Tag[];
    Username: string;
  }
  export namespace User {
    export interface Attr {
      UserArn: string;
    }
    export interface UserIdentityInfo {
      Email?: string;
      FirstName?: string;
      LastName?: string;
      Mobile?: string;
      SecondaryEmail?: string;
    }
    export interface UserPhoneConfig {
      AfterContactWorkTimeLimit?: number;
      AutoAccept?: boolean;
      DeskPhoneNumber?: string;
      PhoneType: string;
    }
  }
  export interface UserHierarchyGroup {
    InstanceArn: string;
    Name: string;
    ParentGroupArn?: string;
  }
}
export namespace ConnectCampaigns {
  export interface Campaign {
    ConnectInstanceArn: string;
    DialerConfig: Campaign.DialerConfig;
    Name: string;
    OutboundCallConfig: Campaign.OutboundCallConfig;
    Tags?: Tag[];
  }
  export namespace Campaign {
    export interface Attr {
      Arn: string;
    }
    export interface DialerConfig {
      PredictiveDialerConfig?: PredictiveDialerConfig;
      ProgressiveDialerConfig?: ProgressiveDialerConfig;
    }
    export interface OutboundCallConfig {
      ConnectContactFlowArn: string;
      ConnectQueueArn: string;
      ConnectSourcePhoneNumber?: string;
    }
    export interface PredictiveDialerConfig {
      BandwidthAllocation: number;
    }
    export interface ProgressiveDialerConfig {
      BandwidthAllocation: number;
    }
  }
}
export namespace ControlTower {
  export interface EnabledControl {
    ControlIdentifier: string;
    TargetIdentifier: string;
  }
}
export namespace CustomerProfiles {
  export interface Domain {
    DeadLetterQueueUrl?: string;
    DefaultEncryptionKey?: string;
    DefaultExpirationDays?: number;
    DomainName: string;
    Tags?: Tag[];
  }
  export interface Integration {
    DomainName: string;
    FlowDefinition?: Integration.FlowDefinition;
    ObjectTypeName?: string;
    ObjectTypeNames?: Integration.ObjectTypeMapping[];
    Tags?: Tag[];
    Uri?: string;
  }
  export namespace Integration {
    export interface Attr {
      CreatedAt: string;
      LastUpdatedAt: string;
    }
    export interface ConnectorOperator {
      Marketo?: string;
      S3?: string;
      Salesforce?: string;
      ServiceNow?: string;
      Zendesk?: string;
    }
    export interface FlowDefinition {
      Description?: string;
      FlowName: string;
      KmsArn: string;
      SourceFlowConfig: SourceFlowConfig;
      Tasks: Task[];
      TriggerConfig: TriggerConfig;
    }
    export interface IncrementalPullConfig {
      DatetimeTypeFieldName?: string;
    }
    export interface MarketoSourceProperties {
      Object: string;
    }
    export interface ObjectTypeMapping {
      Key: string;
      Value: string;
    }
    export interface S3SourceProperties {
      BucketName: string;
      BucketPrefix?: string;
    }
    export interface SalesforceSourceProperties {
      EnableDynamicFieldUpdate?: boolean;
      IncludeDeletedRecords?: boolean;
      Object: string;
    }
    export interface ScheduledTriggerProperties {
      DataPullMode?: string;
      FirstExecutionFrom?: number;
      ScheduleEndTime?: number;
      ScheduleExpression: string;
      ScheduleOffset?: number;
      ScheduleStartTime?: number;
      Timezone?: string;
    }
    export interface ServiceNowSourceProperties {
      Object: string;
    }
    export interface SourceConnectorProperties {
      Marketo?: MarketoSourceProperties;
      S3?: S3SourceProperties;
      Salesforce?: SalesforceSourceProperties;
      ServiceNow?: ServiceNowSourceProperties;
      Zendesk?: ZendeskSourceProperties;
    }
    export interface SourceFlowConfig {
      ConnectorProfileName?: string;
      ConnectorType: string;
      IncrementalPullConfig?: IncrementalPullConfig;
      SourceConnectorProperties: SourceConnectorProperties;
    }
    export interface Task {
      ConnectorOperator?: ConnectorOperator;
      DestinationField?: string;
      SourceFields: string[];
      TaskProperties?: TaskPropertiesMap[];
      TaskType: string;
    }
    export interface TaskPropertiesMap {
      OperatorPropertyKey: string;
      Property: string;
    }
    export interface TriggerConfig {
      TriggerProperties?: TriggerProperties;
      TriggerType: string;
    }
    export interface TriggerProperties {
      Scheduled?: ScheduledTriggerProperties;
    }
    export interface ZendeskSourceProperties {
      Object: string;
    }
  }
  export interface ObjectType {
    AllowProfileCreation?: boolean;
    Description?: string;
    DomainName: string;
    EncryptionKey?: string;
    ExpirationDays?: number;
    Fields?: ObjectType.FieldMap[];
    Keys?: ObjectType.KeyMap[];
    ObjectTypeName?: string;
    Tags?: Tag[];
    TemplateId?: string;
  }
  export namespace ObjectType {
    export interface Attr {
      CreatedAt: string;
      LastUpdatedAt: string;
    }
    export interface FieldMap {
      Name?: string;
      ObjectTypeField?: ObjectTypeField;
    }
    export interface KeyMap {
      Name?: string;
      ObjectTypeKeyList?: ObjectTypeKey[];
    }
    export interface ObjectTypeField {
      ContentType?: string;
      Source?: string;
      Target?: string;
    }
    export interface ObjectTypeKey {
      FieldNames?: string[];
      StandardIdentifiers?: string[];
    }
  }
}
export namespace DAX {
  export interface Cluster {
    AvailabilityZones?: string[];
    ClusterEndpointEncryptionType?: string;
    ClusterName?: string;
    Description?: string;
    IAMRoleARN: string;
    NodeType: string;
    NotificationTopicARN?: string;
    ParameterGroupName?: string;
    PreferredMaintenanceWindow?: string;
    ReplicationFactor: number;
    SSESpecification?: Cluster.SSESpecification;
    SecurityGroupIds?: string[];
    SubnetGroupName?: string;
    Tags?: any;
  }
  export namespace Cluster {
    export interface Attr {
      Arn: string;
      ClusterDiscoveryEndpoint: string;
      ClusterDiscoveryEndpointURL: string;
    }
    export interface SSESpecification {
      SSEEnabled?: boolean;
    }
  }
  export interface ParameterGroup {
    Description?: string;
    ParameterGroupName?: string;
    ParameterNameValues?: any;
  }
  export interface SubnetGroup {
    Description?: string;
    SubnetGroupName?: string;
    SubnetIds: string[];
  }
}
export namespace DLM {
  export interface LifecyclePolicy {
    Description?: string;
    ExecutionRoleArn?: string;
    PolicyDetails?: LifecyclePolicy.PolicyDetails;
    State?: string;
    Tags?: Tag[];
  }
  export namespace LifecyclePolicy {
    export interface Attr {
      Arn: string;
    }
    export interface Action {
      CrossRegionCopy: CrossRegionCopyAction[];
      Name: string;
    }
    export interface ArchiveRetainRule {
      RetentionArchiveTier: RetentionArchiveTier;
    }
    export interface ArchiveRule {
      RetainRule: ArchiveRetainRule;
    }
    export interface CreateRule {
      CronExpression?: string;
      Interval?: number;
      IntervalUnit?: string;
      Location?: string;
      Times?: string[];
    }
    export interface CrossRegionCopyAction {
      EncryptionConfiguration: EncryptionConfiguration;
      RetainRule?: CrossRegionCopyRetainRule;
      Target: string;
    }
    export interface CrossRegionCopyDeprecateRule {
      Interval: number;
      IntervalUnit: string;
    }
    export interface CrossRegionCopyRetainRule {
      Interval: number;
      IntervalUnit: string;
    }
    export interface CrossRegionCopyRule {
      CmkArn?: string;
      CopyTags?: boolean;
      DeprecateRule?: CrossRegionCopyDeprecateRule;
      Encrypted: boolean;
      RetainRule?: CrossRegionCopyRetainRule;
      Target?: string;
      TargetRegion?: string;
    }
    export interface DeprecateRule {
      Count?: number;
      Interval?: number;
      IntervalUnit?: string;
    }
    export interface EncryptionConfiguration {
      CmkArn?: string;
      Encrypted: boolean;
    }
    export interface EventParameters {
      DescriptionRegex?: string;
      EventType: string;
      SnapshotOwner: string[];
    }
    export interface EventSource {
      Parameters?: EventParameters;
      Type: string;
    }
    export interface FastRestoreRule {
      AvailabilityZones?: string[];
      Count?: number;
      Interval?: number;
      IntervalUnit?: string;
    }
    export interface Parameters {
      ExcludeBootVolume?: boolean;
      ExcludeDataVolumeTags?: Tag[];
      NoReboot?: boolean;
    }
    export interface PolicyDetails {
      Actions?: Action[];
      EventSource?: EventSource;
      Parameters?: Parameters;
      PolicyType?: string;
      ResourceLocations?: string[];
      ResourceTypes?: string[];
      Schedules?: Schedule[];
      TargetTags?: Tag[];
    }
    export interface RetainRule {
      Count?: number;
      Interval?: number;
      IntervalUnit?: string;
    }
    export interface RetentionArchiveTier {
      Count?: number;
      Interval?: number;
      IntervalUnit?: string;
    }
    export interface Schedule {
      ArchiveRule?: ArchiveRule;
      CopyTags?: boolean;
      CreateRule?: CreateRule;
      CrossRegionCopyRules?: CrossRegionCopyRule[];
      DeprecateRule?: DeprecateRule;
      FastRestoreRule?: FastRestoreRule;
      Name?: string;
      RetainRule?: RetainRule;
      ShareRules?: ShareRule[];
      TagsToAdd?: Tag[];
      VariableTags?: Tag[];
    }
    export interface ShareRule {
      TargetAccounts?: string[];
      UnshareInterval?: number;
      UnshareIntervalUnit?: string;
    }
  }
}
export namespace DMS {
  export interface Certificate {
    CertificateIdentifier?: string;
    CertificatePem?: string;
    CertificateWallet?: string;
  }
  export interface Endpoint {
    CertificateArn?: string;
    DatabaseName?: string;
    DocDbSettings?: Endpoint.DocDbSettings;
    DynamoDbSettings?: Endpoint.DynamoDbSettings;
    ElasticsearchSettings?: Endpoint.ElasticsearchSettings;
    EndpointIdentifier?: string;
    EndpointType: string;
    EngineName: string;
    ExtraConnectionAttributes?: string;
    GcpMySQLSettings?: Endpoint.GcpMySQLSettings;
    IbmDb2Settings?: Endpoint.IbmDb2Settings;
    KafkaSettings?: Endpoint.KafkaSettings;
    KinesisSettings?: Endpoint.KinesisSettings;
    KmsKeyId?: string;
    MicrosoftSqlServerSettings?: Endpoint.MicrosoftSqlServerSettings;
    MongoDbSettings?: Endpoint.MongoDbSettings;
    MySqlSettings?: Endpoint.MySqlSettings;
    NeptuneSettings?: Endpoint.NeptuneSettings;
    OracleSettings?: Endpoint.OracleSettings;
    Password?: string;
    Port?: number;
    PostgreSqlSettings?: Endpoint.PostgreSqlSettings;
    RedisSettings?: Endpoint.RedisSettings;
    RedshiftSettings?: Endpoint.RedshiftSettings;
    ResourceIdentifier?: string;
    S3Settings?: Endpoint.S3Settings;
    ServerName?: string;
    SslMode?: string;
    SybaseSettings?: Endpoint.SybaseSettings;
    Tags?: Tag[];
    Username?: string;
  }
  export namespace Endpoint {
    export interface Attr {
      ExternalId: string;
    }
    export interface DocDbSettings {
      DocsToInvestigate?: number;
      ExtractDocId?: boolean;
      NestingLevel?: string;
      SecretsManagerAccessRoleArn?: string;
      SecretsManagerSecretId?: string;
    }
    export interface DynamoDbSettings {
      ServiceAccessRoleArn?: string;
    }
    export interface ElasticsearchSettings {
      EndpointUri?: string;
      ErrorRetryDuration?: number;
      FullLoadErrorPercentage?: number;
      ServiceAccessRoleArn?: string;
    }
    export interface GcpMySQLSettings {
      AfterConnectScript?: string;
      CleanSourceMetadataOnMismatch?: boolean;
      DatabaseName?: string;
      EventsPollInterval?: number;
      MaxFileSize?: number;
      ParallelLoadThreads?: number;
      Password?: string;
      Port?: number;
      SecretsManagerAccessRoleArn?: string;
      SecretsManagerSecretId?: string;
      ServerName?: string;
      ServerTimezone?: string;
      Username?: string;
    }
    export interface IbmDb2Settings {
      CurrentLsn?: string;
      MaxKBytesPerRead?: number;
      SecretsManagerAccessRoleArn?: string;
      SecretsManagerSecretId?: string;
      SetDataCaptureChanges?: boolean;
    }
    export interface KafkaSettings {
      Broker?: string;
      IncludeControlDetails?: boolean;
      IncludeNullAndEmpty?: boolean;
      IncludePartitionValue?: boolean;
      IncludeTableAlterOperations?: boolean;
      IncludeTransactionDetails?: boolean;
      MessageFormat?: string;
      MessageMaxBytes?: number;
      NoHexPrefix?: boolean;
      PartitionIncludeSchemaTable?: boolean;
      SaslPassword?: string;
      SaslUserName?: string;
      SecurityProtocol?: string;
      SslCaCertificateArn?: string;
      SslClientCertificateArn?: string;
      SslClientKeyArn?: string;
      SslClientKeyPassword?: string;
      Topic?: string;
    }
    export interface KinesisSettings {
      IncludeControlDetails?: boolean;
      IncludeNullAndEmpty?: boolean;
      IncludePartitionValue?: boolean;
      IncludeTableAlterOperations?: boolean;
      IncludeTransactionDetails?: boolean;
      MessageFormat?: string;
      NoHexPrefix?: boolean;
      PartitionIncludeSchemaTable?: boolean;
      ServiceAccessRoleArn?: string;
      StreamArn?: string;
    }
    export interface MicrosoftSqlServerSettings {
      BcpPacketSize?: number;
      ControlTablesFileGroup?: string;
      QuerySingleAlwaysOnNode?: boolean;
      ReadBackupOnly?: boolean;
      SafeguardPolicy?: string;
      SecretsManagerAccessRoleArn?: string;
      SecretsManagerSecretId?: string;
      UseBcpFullLoad?: boolean;
      UseThirdPartyBackupDevice?: boolean;
    }
    export interface MongoDbSettings {
      AuthMechanism?: string;
      AuthSource?: string;
      AuthType?: string;
      DatabaseName?: string;
      DocsToInvestigate?: string;
      ExtractDocId?: string;
      NestingLevel?: string;
      Password?: string;
      Port?: number;
      SecretsManagerAccessRoleArn?: string;
      SecretsManagerSecretId?: string;
      ServerName?: string;
      Username?: string;
    }
    export interface MySqlSettings {
      AfterConnectScript?: string;
      CleanSourceMetadataOnMismatch?: boolean;
      EventsPollInterval?: number;
      MaxFileSize?: number;
      ParallelLoadThreads?: number;
      SecretsManagerAccessRoleArn?: string;
      SecretsManagerSecretId?: string;
      ServerTimezone?: string;
      TargetDbType?: string;
    }
    export interface NeptuneSettings {
      ErrorRetryDuration?: number;
      IamAuthEnabled?: boolean;
      MaxFileSize?: number;
      MaxRetryCount?: number;
      S3BucketFolder?: string;
      S3BucketName?: string;
      ServiceAccessRoleArn?: string;
    }
    export interface OracleSettings {
      AccessAlternateDirectly?: boolean;
      AddSupplementalLogging?: boolean;
      AdditionalArchivedLogDestId?: number;
      AllowSelectNestedTables?: boolean;
      ArchivedLogDestId?: number;
      ArchivedLogsOnly?: boolean;
      AsmPassword?: string;
      AsmServer?: string;
      AsmUser?: string;
      CharLengthSemantics?: string;
      DirectPathNoLog?: boolean;
      DirectPathParallelLoad?: boolean;
      EnableHomogenousTablespace?: boolean;
      ExtraArchivedLogDestIds?: number[];
      FailTasksOnLobTruncation?: boolean;
      NumberDatatypeScale?: number;
      OraclePathPrefix?: string;
      ParallelAsmReadThreads?: number;
      ReadAheadBlocks?: number;
      ReadTableSpaceName?: boolean;
      ReplacePathPrefix?: boolean;
      RetryInterval?: number;
      SecretsManagerAccessRoleArn?: string;
      SecretsManagerOracleAsmAccessRoleArn?: string;
      SecretsManagerOracleAsmSecretId?: string;
      SecretsManagerSecretId?: string;
      SecurityDbEncryption?: string;
      SecurityDbEncryptionName?: string;
      SpatialDataOptionToGeoJsonFunctionName?: string;
      StandbyDelayTime?: number;
      UseAlternateFolderForOnline?: boolean;
      UseBFile?: boolean;
      UseDirectPathFullLoad?: boolean;
      UseLogminerReader?: boolean;
      UsePathPrefix?: string;
    }
    export interface PostgreSqlSettings {
      AfterConnectScript?: string;
      CaptureDdls?: boolean;
      DdlArtifactsSchema?: string;
      ExecuteTimeout?: number;
      FailTasksOnLobTruncation?: boolean;
      HeartbeatEnable?: boolean;
      HeartbeatFrequency?: number;
      HeartbeatSchema?: string;
      MaxFileSize?: number;
      PluginName?: string;
      SecretsManagerAccessRoleArn?: string;
      SecretsManagerSecretId?: string;
      SlotName?: string;
    }
    export interface RedisSettings {
      AuthPassword?: string;
      AuthType?: string;
      AuthUserName?: string;
      Port?: number;
      ServerName?: string;
      SslCaCertificateArn?: string;
      SslSecurityProtocol?: string;
    }
    export interface RedshiftSettings {
      AcceptAnyDate?: boolean;
      AfterConnectScript?: string;
      BucketFolder?: string;
      BucketName?: string;
      CaseSensitiveNames?: boolean;
      CompUpdate?: boolean;
      ConnectionTimeout?: number;
      DateFormat?: string;
      EmptyAsNull?: boolean;
      EncryptionMode?: string;
      ExplicitIds?: boolean;
      FileTransferUploadStreams?: number;
      LoadTimeout?: number;
      MaxFileSize?: number;
      RemoveQuotes?: boolean;
      ReplaceChars?: string;
      ReplaceInvalidChars?: string;
      SecretsManagerAccessRoleArn?: string;
      SecretsManagerSecretId?: string;
      ServerSideEncryptionKmsKeyId?: string;
      ServiceAccessRoleArn?: string;
      TimeFormat?: string;
      TrimBlanks?: boolean;
      TruncateColumns?: boolean;
      WriteBufferSize?: number;
    }
    export interface S3Settings {
      AddColumnName?: boolean;
      BucketFolder?: string;
      BucketName?: string;
      CannedAclForObjects?: string;
      CdcInsertsAndUpdates?: boolean;
      CdcInsertsOnly?: boolean;
      CdcMaxBatchInterval?: number;
      CdcMinFileSize?: number;
      CdcPath?: string;
      CompressionType?: string;
      CsvDelimiter?: string;
      CsvNoSupValue?: string;
      CsvNullValue?: string;
      CsvRowDelimiter?: string;
      DataFormat?: string;
      DataPageSize?: number;
      DatePartitionDelimiter?: string;
      DatePartitionEnabled?: boolean;
      DatePartitionSequence?: string;
      DatePartitionTimezone?: string;
      DictPageSizeLimit?: number;
      EnableStatistics?: boolean;
      EncodingType?: string;
      EncryptionMode?: string;
      ExternalTableDefinition?: string;
      IgnoreHeaderRows?: number;
      IncludeOpForFullLoad?: boolean;
      MaxFileSize?: number;
      ParquetTimestampInMillisecond?: boolean;
      ParquetVersion?: string;
      PreserveTransactions?: boolean;
      Rfc4180?: boolean;
      RowGroupLength?: number;
      ServerSideEncryptionKmsKeyId?: string;
      ServiceAccessRoleArn?: string;
      TimestampColumnName?: string;
      UseCsvNoSupValue?: boolean;
      UseTaskStartTimeForFullLoadTimestamp?: boolean;
    }
    export interface SybaseSettings {
      SecretsManagerAccessRoleArn?: string;
      SecretsManagerSecretId?: string;
    }
  }
  export interface EventSubscription {
    Enabled?: boolean;
    EventCategories?: string[];
    SnsTopicArn: string;
    SourceIds?: string[];
    SourceType?: string;
    SubscriptionName?: string;
    Tags?: Tag[];
  }
  export interface ReplicationInstance {
    AllocatedStorage?: number;
    AllowMajorVersionUpgrade?: boolean;
    AutoMinorVersionUpgrade?: boolean;
    AvailabilityZone?: string;
    EngineVersion?: string;
    KmsKeyId?: string;
    MultiAZ?: boolean;
    PreferredMaintenanceWindow?: string;
    PubliclyAccessible?: boolean;
    ReplicationInstanceClass: string;
    ReplicationInstanceIdentifier?: string;
    ReplicationSubnetGroupIdentifier?: string;
    ResourceIdentifier?: string;
    Tags?: Tag[];
    VpcSecurityGroupIds?: string[];
  }
  export interface ReplicationSubnetGroup {
    ReplicationSubnetGroupDescription: string;
    ReplicationSubnetGroupIdentifier?: string;
    SubnetIds: string[];
    Tags?: Tag[];
  }
  export interface ReplicationTask {
    CdcStartPosition?: string;
    CdcStartTime?: number;
    CdcStopPosition?: string;
    MigrationType: string;
    ReplicationInstanceArn: string;
    ReplicationTaskIdentifier?: string;
    ReplicationTaskSettings?: string;
    ResourceIdentifier?: string;
    SourceEndpointArn: string;
    TableMappings: string;
    Tags?: Tag[];
    TargetEndpointArn: string;
    TaskData?: string;
  }
}
export namespace DataBrew {
  export interface Dataset {
    Format?: string;
    FormatOptions?: Dataset.FormatOptions;
    Input: Dataset.Input;
    Name: string;
    PathOptions?: Dataset.PathOptions;
    Tags?: Tag[];
  }
  export namespace Dataset {
    export interface Attr {}
    export interface CsvOptions {
      Delimiter?: string;
      HeaderRow?: boolean;
    }
    export interface DataCatalogInputDefinition {
      CatalogId?: string;
      DatabaseName?: string;
      TableName?: string;
      TempDirectory?: S3Location;
    }
    export interface DatabaseInputDefinition {
      DatabaseTableName?: string;
      GlueConnectionName: string;
      QueryString?: string;
      TempDirectory?: S3Location;
    }
    export interface DatasetParameter {
      CreateColumn?: boolean;
      DatetimeOptions?: DatetimeOptions;
      Filter?: FilterExpression;
      Name: string;
      Type: string;
    }
    export interface DatetimeOptions {
      Format: string;
      LocaleCode?: string;
      TimezoneOffset?: string;
    }
    export interface ExcelOptions {
      HeaderRow?: boolean;
      SheetIndexes?: number[];
      SheetNames?: string[];
    }
    export interface FilesLimit {
      MaxFiles: number;
      Order?: string;
      OrderedBy?: string;
    }
    export interface FilterExpression {
      Expression: string;
      ValuesMap: FilterValue[];
    }
    export interface FilterValue {
      Value: string;
      ValueReference: string;
    }
    export interface FormatOptions {
      Csv?: CsvOptions;
      Excel?: ExcelOptions;
      Json?: JsonOptions;
    }
    export interface Input {
      DataCatalogInputDefinition?: DataCatalogInputDefinition;
      DatabaseInputDefinition?: DatabaseInputDefinition;
      Metadata?: Metadata;
      S3InputDefinition?: S3Location;
    }
    export interface JsonOptions {
      MultiLine?: boolean;
    }
    export interface Metadata {
      SourceArn?: string;
    }
    export interface PathOptions {
      FilesLimit?: FilesLimit;
      LastModifiedDateCondition?: FilterExpression;
      Parameters?: PathParameter[];
    }
    export interface PathParameter {
      DatasetParameter: DatasetParameter;
      PathParameterName: string;
    }
    export interface S3Location {
      Bucket: string;
      Key?: string;
    }
  }
  export interface Job {
    DataCatalogOutputs?: Job.DataCatalogOutput[];
    DatabaseOutputs?: Job.DatabaseOutput[];
    DatasetName?: string;
    EncryptionKeyArn?: string;
    EncryptionMode?: string;
    JobSample?: Job.JobSample;
    LogSubscription?: string;
    MaxCapacity?: number;
    MaxRetries?: number;
    Name: string;
    OutputLocation?: Job.OutputLocation;
    Outputs?: Job.Output[];
    ProfileConfiguration?: Job.ProfileConfiguration;
    ProjectName?: string;
    Recipe?: Job.Recipe;
    RoleArn: string;
    Tags?: Tag[];
    Timeout?: number;
    Type: string;
    ValidationConfigurations?: Job.ValidationConfiguration[];
  }
  export namespace Job {
    export interface Attr {}
    export interface AllowedStatistics {
      Statistics: string[];
    }
    export interface ColumnSelector {
      Name?: string;
      Regex?: string;
    }
    export interface ColumnStatisticsConfiguration {
      Selectors?: ColumnSelector[];
      Statistics: StatisticsConfiguration;
    }
    export interface CsvOutputOptions {
      Delimiter?: string;
    }
    export interface DataCatalogOutput {
      CatalogId?: string;
      DatabaseName: string;
      DatabaseOptions?: DatabaseTableOutputOptions;
      Overwrite?: boolean;
      S3Options?: S3TableOutputOptions;
      TableName: string;
    }
    export interface DatabaseOutput {
      DatabaseOptions: DatabaseTableOutputOptions;
      DatabaseOutputMode?: string;
      GlueConnectionName: string;
    }
    export interface DatabaseTableOutputOptions {
      TableName: string;
      TempDirectory?: S3Location;
    }
    export interface EntityDetectorConfiguration {
      AllowedStatistics?: AllowedStatistics;
      EntityTypes: string[];
    }
    export interface JobSample {
      Mode?: string;
      Size?: number;
    }
    export interface Output {
      CompressionFormat?: string;
      Format?: string;
      FormatOptions?: OutputFormatOptions;
      Location: S3Location;
      MaxOutputFiles?: number;
      Overwrite?: boolean;
      PartitionColumns?: string[];
    }
    export interface OutputFormatOptions {
      Csv?: CsvOutputOptions;
    }
    export interface OutputLocation {
      Bucket: string;
      BucketOwner?: string;
      Key?: string;
    }
    export interface ProfileConfiguration {
      ColumnStatisticsConfigurations?: ColumnStatisticsConfiguration[];
      DatasetStatisticsConfiguration?: StatisticsConfiguration;
      EntityDetectorConfiguration?: EntityDetectorConfiguration;
      ProfileColumns?: ColumnSelector[];
    }
    export interface Recipe {
      Name: string;
      Version?: string;
    }
    export interface S3Location {
      Bucket: string;
      BucketOwner?: string;
      Key?: string;
    }
    export interface S3TableOutputOptions {
      Location: S3Location;
    }
    export interface StatisticOverride {
      Parameters: Record<string, string>;
      Statistic: string;
    }
    export interface StatisticsConfiguration {
      IncludedStatistics?: string[];
      Overrides?: StatisticOverride[];
    }
    export interface ValidationConfiguration {
      RulesetArn: string;
      ValidationMode?: string;
    }
  }
  export interface Project {
    DatasetName: string;
    Name: string;
    RecipeName: string;
    RoleArn: string;
    Sample?: Project.Sample;
    Tags?: Tag[];
  }
  export namespace Project {
    export interface Attr {}
    export interface Sample {
      Size?: number;
      Type: string;
    }
  }
  export interface Recipe {
    Description?: string;
    Name: string;
    Steps: Recipe.RecipeStep[];
    Tags?: Tag[];
  }
  export namespace Recipe {
    export interface Attr {}
    export interface Action {
      Operation: string;
      Parameters?: Record<string, string>;
    }
    export interface ConditionExpression {
      Condition: string;
      TargetColumn: string;
      Value?: string;
    }
    export interface DataCatalogInputDefinition {
      CatalogId?: string;
      DatabaseName?: string;
      TableName?: string;
      TempDirectory?: S3Location;
    }
    export interface Input {
      DataCatalogInputDefinition?: DataCatalogInputDefinition;
      S3InputDefinition?: S3Location;
    }
    export interface RecipeParameters {
      AggregateFunction?: string;
      Base?: string;
      CaseStatement?: string;
      CategoryMap?: string;
      CharsToRemove?: string;
      CollapseConsecutiveWhitespace?: string;
      ColumnDataType?: string;
      ColumnRange?: string;
      Count?: string;
      CustomCharacters?: string;
      CustomStopWords?: string;
      CustomValue?: string;
      DatasetsColumns?: string;
      DateAddValue?: string;
      DateTimeFormat?: string;
      DateTimeParameters?: string;
      DeleteOtherRows?: string;
      Delimiter?: string;
      EndPattern?: string;
      EndPosition?: string;
      EndValue?: string;
      ExpandContractions?: string;
      Exponent?: string;
      FalseString?: string;
      GroupByAggFunctionOptions?: string;
      GroupByColumns?: string;
      HiddenColumns?: string;
      IgnoreCase?: string;
      IncludeInSplit?: string;
      Input?: any;
      Interval?: string;
      IsText?: string;
      JoinKeys?: string;
      JoinType?: string;
      LeftColumns?: string;
      Limit?: string;
      LowerBound?: string;
      MapType?: string;
      ModeType?: string;
      MultiLine?: boolean;
      NumRows?: string;
      NumRowsAfter?: string;
      NumRowsBefore?: string;
      OrderByColumn?: string;
      OrderByColumns?: string;
      Other?: string;
      Pattern?: string;
      PatternOption1?: string;
      PatternOption2?: string;
      PatternOptions?: string;
      Period?: string;
      Position?: string;
      RemoveAllPunctuation?: string;
      RemoveAllQuotes?: string;
      RemoveAllWhitespace?: string;
      RemoveCustomCharacters?: string;
      RemoveCustomValue?: string;
      RemoveLeadingAndTrailingPunctuation?: string;
      RemoveLeadingAndTrailingQuotes?: string;
      RemoveLeadingAndTrailingWhitespace?: string;
      RemoveLetters?: string;
      RemoveNumbers?: string;
      RemoveSourceColumn?: string;
      RemoveSpecialCharacters?: string;
      RightColumns?: string;
      SampleSize?: string;
      SampleType?: string;
      SecondInput?: string;
      SecondaryInputs?: SecondaryInput[];
      SheetIndexes?: number[];
      SheetNames?: string[];
      SourceColumn?: string;
      SourceColumn1?: string;
      SourceColumn2?: string;
      SourceColumns?: string;
      StartColumnIndex?: string;
      StartPattern?: string;
      StartPosition?: string;
      StartValue?: string;
      StemmingMode?: string;
      StepCount?: string;
      StepIndex?: string;
      StopWordsMode?: string;
      Strategy?: string;
      TargetColumn?: string;
      TargetColumnNames?: string;
      TargetDateFormat?: string;
      TargetIndex?: string;
      TimeZone?: string;
      TokenizerPattern?: string;
      TrueString?: string;
      UdfLang?: string;
      Units?: string;
      UnpivotColumn?: string;
      UpperBound?: string;
      UseNewDataFrame?: string;
      Value?: string;
      Value1?: string;
      Value2?: string;
      ValueColumn?: string;
      ViewFrame?: string;
    }
    export interface RecipeStep {
      Action: Action;
      ConditionExpressions?: ConditionExpression[];
    }
    export interface S3Location {
      Bucket: string;
      Key?: string;
    }
    export interface SecondaryInput {
      DataCatalogInputDefinition?: DataCatalogInputDefinition;
      S3InputDefinition?: S3Location;
    }
  }
  export interface Ruleset {
    Description?: string;
    Name: string;
    Rules: Ruleset.Rule[];
    Tags?: Tag[];
    TargetArn: string;
  }
  export namespace Ruleset {
    export interface Attr {}
    export interface ColumnSelector {
      Name?: string;
      Regex?: string;
    }
    export interface Rule {
      CheckExpression: string;
      ColumnSelectors?: ColumnSelector[];
      Disabled?: boolean;
      Name: string;
      SubstitutionMap?: SubstitutionValue[];
      Threshold?: Threshold;
    }
    export interface SubstitutionValue {
      Value: string;
      ValueReference: string;
    }
    export interface Threshold {
      Type?: string;
      Unit?: string;
      Value: number;
    }
  }
  export interface Schedule {
    CronExpression: string;
    JobNames?: string[];
    Name: string;
    Tags?: Tag[];
  }
}
export namespace DataPipeline {
  export interface Pipeline {
    Activate?: boolean;
    Description?: string;
    Name: string;
    ParameterObjects?: Pipeline.ParameterObject[];
    ParameterValues?: Pipeline.ParameterValue[];
    PipelineObjects?: Pipeline.PipelineObject[];
    PipelineTags?: Pipeline.PipelineTag[];
  }
  export namespace Pipeline {
    export interface Attr {
      PipelineId: string;
    }
    export interface Field {
      Key: string;
      RefValue?: string;
      StringValue?: string;
    }
    export interface ParameterAttribute {
      Key: string;
      StringValue: string;
    }
    export interface ParameterObject {
      Attributes: ParameterAttribute[];
      Id: string;
    }
    export interface ParameterValue {
      Id: string;
      StringValue: string;
    }
    export interface PipelineObject {
      Fields: Field[];
      Id: string;
      Name: string;
    }
    export interface PipelineTag {
      Key: string;
      Value: string;
    }
  }
}
export namespace DataSync {
  export interface Agent {
    ActivationKey: string;
    AgentName?: string;
    SecurityGroupArns?: string[];
    SubnetArns?: string[];
    Tags?: Tag[];
    VpcEndpointId?: string;
  }
  export interface LocationEFS {
    AccessPointArn?: string;
    Ec2Config: LocationEFS.Ec2Config;
    EfsFilesystemArn?: string;
    FileSystemAccessRoleArn?: string;
    InTransitEncryption?: string;
    Subdirectory?: string;
    Tags?: Tag[];
  }
  export namespace LocationEFS {
    export interface Attr {
      LocationArn: string;
      LocationUri: string;
    }
    export interface Ec2Config {
      SecurityGroupArns: string[];
      SubnetArn: string;
    }
  }
  export interface LocationFSxLustre {
    FsxFilesystemArn?: string;
    SecurityGroupArns: string[];
    Subdirectory?: string;
    Tags?: Tag[];
  }
  export interface LocationFSxONTAP {
    Protocol: LocationFSxONTAP.Protocol;
    SecurityGroupArns: string[];
    StorageVirtualMachineArn: string;
    Subdirectory?: string;
    Tags?: Tag[];
  }
  export namespace LocationFSxONTAP {
    export interface Attr {
      FsxFilesystemArn: string;
      LocationArn: string;
      LocationUri: string;
    }
    export interface NFS {
      MountOptions: NfsMountOptions;
    }
    export interface NfsMountOptions {
      Version?: string;
    }
    export interface Protocol {
      NFS?: NFS;
      SMB?: SMB;
    }
    export interface SMB {
      Domain?: string;
      MountOptions: SmbMountOptions;
      Password: string;
      User: string;
    }
    export interface SmbMountOptions {
      Version?: string;
    }
  }
  export interface LocationFSxOpenZFS {
    FsxFilesystemArn: string;
    Protocol: LocationFSxOpenZFS.Protocol;
    SecurityGroupArns: string[];
    Subdirectory?: string;
    Tags?: Tag[];
  }
  export namespace LocationFSxOpenZFS {
    export interface Attr {
      LocationArn: string;
      LocationUri: string;
    }
    export interface MountOptions {
      Version?: string;
    }
    export interface NFS {
      MountOptions: MountOptions;
    }
    export interface Protocol {
      NFS?: NFS;
    }
  }
  export interface LocationFSxWindows {
    Domain?: string;
    FsxFilesystemArn?: string;
    Password?: string;
    SecurityGroupArns: string[];
    Subdirectory?: string;
    Tags?: Tag[];
    User: string;
  }
  export interface LocationHDFS {
    AgentArns: string[];
    AuthenticationType: string;
    BlockSize?: number;
    KerberosKeytab?: string;
    KerberosKrb5Conf?: string;
    KerberosPrincipal?: string;
    KmsKeyProviderUri?: string;
    NameNodes: LocationHDFS.NameNode[];
    QopConfiguration?: LocationHDFS.QopConfiguration;
    ReplicationFactor?: number;
    SimpleUser?: string;
    Subdirectory?: string;
    Tags?: Tag[];
  }
  export namespace LocationHDFS {
    export interface Attr {
      LocationArn: string;
      LocationUri: string;
    }
    export interface NameNode {
      Hostname: string;
      Port: number;
    }
    export interface QopConfiguration {
      DataTransferProtection?: string;
      RpcProtection?: string;
    }
  }
  export interface LocationNFS {
    MountOptions?: LocationNFS.MountOptions;
    OnPremConfig: LocationNFS.OnPremConfig;
    ServerHostname?: string;
    Subdirectory?: string;
    Tags?: Tag[];
  }
  export namespace LocationNFS {
    export interface Attr {
      LocationArn: string;
      LocationUri: string;
    }
    export interface MountOptions {
      Version?: string;
    }
    export interface OnPremConfig {
      AgentArns: string[];
    }
  }
  export interface LocationObjectStorage {
    AccessKey?: string;
    AgentArns: string[];
    BucketName?: string;
    SecretKey?: string;
    ServerHostname?: string;
    ServerPort?: number;
    ServerProtocol?: string;
    Subdirectory?: string;
    Tags?: Tag[];
  }
  export interface LocationS3 {
    S3BucketArn: string;
    S3Config: LocationS3.S3Config;
    S3StorageClass?: string;
    Subdirectory?: string;
    Tags?: Tag[];
  }
  export namespace LocationS3 {
    export interface Attr {
      LocationArn: string;
      LocationUri: string;
    }
    export interface S3Config {
      BucketAccessRoleArn: string;
    }
  }
  export interface LocationSMB {
    AgentArns: string[];
    Domain?: string;
    MountOptions?: LocationSMB.MountOptions;
    Password?: string;
    ServerHostname?: string;
    Subdirectory?: string;
    Tags?: Tag[];
    User: string;
  }
  export namespace LocationSMB {
    export interface Attr {
      LocationArn: string;
      LocationUri: string;
    }
    export interface MountOptions {
      Version?: string;
    }
  }
  export interface Task {
    CloudWatchLogGroupArn?: string;
    DestinationLocationArn: string;
    Excludes?: Task.FilterRule[];
    Includes?: Task.FilterRule[];
    Name?: string;
    Options?: Task.Options;
    Schedule?: Task.TaskSchedule;
    SourceLocationArn: string;
    Tags?: Tag[];
  }
  export namespace Task {
    export interface Attr {
      DestinationNetworkInterfaceArns: string[];
      SourceNetworkInterfaceArns: string[];
      Status: string;
      TaskArn: string;
    }
    export interface FilterRule {
      FilterType?: string;
      Value?: string;
    }
    export interface Options {
      Atime?: string;
      BytesPerSecond?: number;
      Gid?: string;
      LogLevel?: string;
      Mtime?: string;
      ObjectTags?: string;
      OverwriteMode?: string;
      PosixPermissions?: string;
      PreserveDeletedFiles?: string;
      PreserveDevices?: string;
      SecurityDescriptorCopyFlags?: string;
      TaskQueueing?: string;
      TransferMode?: string;
      Uid?: string;
      VerifyMode?: string;
    }
    export interface TaskSchedule {
      ScheduleExpression: string;
    }
  }
}
export namespace Detective {
  export interface Graph {
    Tags?: Tag[];
  }
  export interface MemberInvitation {
    DisableEmailNotification?: boolean;
    GraphArn: string;
    MemberEmailAddress: string;
    MemberId: string;
    Message?: string;
  }
}
export namespace DevOpsGuru {
  export interface NotificationChannel {
    Config: NotificationChannel.NotificationChannelConfig;
  }
  export namespace NotificationChannel {
    export interface Attr {
      Id: string;
    }
    export interface NotificationChannelConfig {
      Filters?: NotificationFilterConfig;
      Sns?: SnsChannelConfig;
    }
    export interface NotificationFilterConfig {
      MessageTypes?: string[];
      Severities?: string[];
    }
    export interface SnsChannelConfig {
      TopicArn?: string;
    }
  }
  export interface ResourceCollection {
    ResourceCollectionFilter: ResourceCollection.ResourceCollectionFilter;
  }
  export namespace ResourceCollection {
    export interface Attr {
      ResourceCollectionType: string;
    }
    export interface CloudFormationCollectionFilter {
      StackNames?: string[];
    }
    export interface ResourceCollectionFilter {
      CloudFormation?: CloudFormationCollectionFilter;
      Tags?: TagCollection[];
    }
    export interface TagCollection {
      AppBoundaryKey?: string;
      TagValues?: string[];
    }
  }
}
export namespace DirectoryService {
  export interface MicrosoftAD {
    CreateAlias?: boolean;
    Edition?: string;
    EnableSso?: boolean;
    Name: string;
    Password: string;
    ShortName?: string;
    VpcSettings: MicrosoftAD.VpcSettings;
  }
  export namespace MicrosoftAD {
    export interface Attr {
      Alias: string;
      DnsIpAddresses: string[];
    }
    export interface VpcSettings {
      SubnetIds: string[];
      VpcId: string;
    }
  }
  export interface SimpleAD {
    CreateAlias?: boolean;
    Description?: string;
    EnableSso?: boolean;
    Name: string;
    Password?: string;
    ShortName?: string;
    Size: string;
    VpcSettings: SimpleAD.VpcSettings;
  }
  export namespace SimpleAD {
    export interface Attr {
      Alias: string;
      DirectoryId: string;
      DnsIpAddresses: string[];
    }
    export interface VpcSettings {
      SubnetIds: string[];
      VpcId: string;
    }
  }
}
export namespace DocDB {
  export interface DBCluster {
    AvailabilityZones?: string[];
    BackupRetentionPeriod?: number;
    CopyTagsToSnapshot?: boolean;
    DBClusterIdentifier?: string;
    DBClusterParameterGroupName?: string;
    DBSubnetGroupName?: string;
    DeletionProtection?: boolean;
    EnableCloudwatchLogsExports?: string[];
    EngineVersion?: string;
    KmsKeyId?: string;
    MasterUserPassword?: string;
    MasterUsername?: string;
    Port?: number;
    PreferredBackupWindow?: string;
    PreferredMaintenanceWindow?: string;
    RestoreToTime?: string;
    RestoreType?: string;
    SnapshotIdentifier?: string;
    SourceDBClusterIdentifier?: string;
    StorageEncrypted?: boolean;
    Tags?: Tag[];
    UseLatestRestorableTime?: boolean;
    VpcSecurityGroupIds?: string[];
  }
  export interface DBClusterParameterGroup {
    Description: string;
    Family: string;
    Name?: string;
    Parameters: any;
    Tags?: Tag[];
  }
  export interface DBInstance {
    AutoMinorVersionUpgrade?: boolean;
    AvailabilityZone?: string;
    DBClusterIdentifier: string;
    DBInstanceClass: string;
    DBInstanceIdentifier?: string;
    EnablePerformanceInsights?: boolean;
    PreferredMaintenanceWindow?: string;
    Tags?: Tag[];
  }
  export interface DBSubnetGroup {
    DBSubnetGroupDescription: string;
    DBSubnetGroupName?: string;
    SubnetIds: string[];
    Tags?: Tag[];
  }
}
export namespace DocDBElastic {
  export interface Cluster {
    AdminUserName: string;
    AdminUserPassword?: string;
    AuthType: string;
    ClusterName: string;
    KmsKeyId?: string;
    PreferredMaintenanceWindow?: string;
    ShardCapacity: number;
    ShardCount: number;
    SubnetIds?: string[];
    Tags?: Tag[];
    VpcSecurityGroupIds?: string[];
  }
}
export namespace DynamoDB {
  export interface GlobalTable {
    AttributeDefinitions: GlobalTable.AttributeDefinition[];
    BillingMode?: string;
    GlobalSecondaryIndexes?: GlobalTable.GlobalSecondaryIndex[];
    KeySchema: GlobalTable.KeySchema[];
    LocalSecondaryIndexes?: GlobalTable.LocalSecondaryIndex[];
    Replicas: GlobalTable.ReplicaSpecification[];
    SSESpecification?: GlobalTable.SSESpecification;
    StreamSpecification?: GlobalTable.StreamSpecification;
    TableName?: string;
    TimeToLiveSpecification?: GlobalTable.TimeToLiveSpecification;
    WriteProvisionedThroughputSettings?: GlobalTable.WriteProvisionedThroughputSettings;
  }
  export namespace GlobalTable {
    export interface Attr {
      Arn: string;
      StreamArn: string;
      TableId: string;
    }
    export interface AttributeDefinition {
      AttributeName: string;
      AttributeType: string;
    }
    export interface CapacityAutoScalingSettings {
      MaxCapacity: number;
      MinCapacity: number;
      SeedCapacity?: number;
      TargetTrackingScalingPolicyConfiguration: TargetTrackingScalingPolicyConfiguration;
    }
    export interface ContributorInsightsSpecification {
      Enabled: boolean;
    }
    export interface GlobalSecondaryIndex {
      IndexName: string;
      KeySchema: KeySchema[];
      Projection: Projection;
      WriteProvisionedThroughputSettings?: WriteProvisionedThroughputSettings;
    }
    export interface KeySchema {
      AttributeName: string;
      KeyType: string;
    }
    export interface LocalSecondaryIndex {
      IndexName: string;
      KeySchema: KeySchema[];
      Projection: Projection;
    }
    export interface PointInTimeRecoverySpecification {
      PointInTimeRecoveryEnabled?: boolean;
    }
    export interface Projection {
      NonKeyAttributes?: string[];
      ProjectionType?: string;
    }
    export interface ReadProvisionedThroughputSettings {
      ReadCapacityAutoScalingSettings?: CapacityAutoScalingSettings;
      ReadCapacityUnits?: number;
    }
    export interface ReplicaGlobalSecondaryIndexSpecification {
      ContributorInsightsSpecification?: ContributorInsightsSpecification;
      IndexName: string;
      ReadProvisionedThroughputSettings?: ReadProvisionedThroughputSettings;
    }
    export interface ReplicaSSESpecification {
      KMSMasterKeyId: string;
    }
    export interface ReplicaSpecification {
      ContributorInsightsSpecification?: ContributorInsightsSpecification;
      GlobalSecondaryIndexes?: ReplicaGlobalSecondaryIndexSpecification[];
      PointInTimeRecoverySpecification?: PointInTimeRecoverySpecification;
      ReadProvisionedThroughputSettings?: ReadProvisionedThroughputSettings;
      Region: string;
      SSESpecification?: ReplicaSSESpecification;
      TableClass?: string;
      Tags?: Tag[];
    }
    export interface SSESpecification {
      SSEEnabled: boolean;
      SSEType?: string;
    }
    export interface StreamSpecification {
      StreamViewType: string;
    }
    export interface TargetTrackingScalingPolicyConfiguration {
      DisableScaleIn?: boolean;
      ScaleInCooldown?: number;
      ScaleOutCooldown?: number;
      TargetValue: number;
    }
    export interface TimeToLiveSpecification {
      AttributeName?: string;
      Enabled: boolean;
    }
    export interface WriteProvisionedThroughputSettings {
      WriteCapacityAutoScalingSettings?: CapacityAutoScalingSettings;
    }
  }
  export interface Table {
    AttributeDefinitions?: Table.AttributeDefinition[];
    BillingMode?: string;
    ContributorInsightsSpecification?: Table.ContributorInsightsSpecification;
    GlobalSecondaryIndexes?: Table.GlobalSecondaryIndex[];
    ImportSourceSpecification?: Table.ImportSourceSpecification;
    KeySchema: Table.KeySchema[];
    KinesisStreamSpecification?: Table.KinesisStreamSpecification;
    LocalSecondaryIndexes?: Table.LocalSecondaryIndex[];
    PointInTimeRecoverySpecification?: Table.PointInTimeRecoverySpecification;
    ProvisionedThroughput?: Table.ProvisionedThroughput;
    SSESpecification?: Table.SSESpecification;
    StreamSpecification?: Table.StreamSpecification;
    TableClass?: string;
    TableName?: string;
    Tags?: Tag[];
    TimeToLiveSpecification?: Table.TimeToLiveSpecification;
  }
  export namespace Table {
    export interface Attr {
      Arn: string;
      StreamArn: string;
    }
    export interface AttributeDefinition {
      AttributeName: string;
      AttributeType: string;
    }
    export interface ContributorInsightsSpecification {
      Enabled: boolean;
    }
    export interface Csv {
      Delimiter?: string;
      HeaderList?: string[];
    }
    export interface GlobalSecondaryIndex {
      ContributorInsightsSpecification?: ContributorInsightsSpecification;
      IndexName: string;
      KeySchema: KeySchema[];
      Projection: Projection;
      ProvisionedThroughput?: ProvisionedThroughput;
    }
    export interface ImportSourceSpecification {
      InputCompressionType?: string;
      InputFormat: string;
      InputFormatOptions?: InputFormatOptions;
      S3BucketSource: S3BucketSource;
    }
    export interface InputFormatOptions {
      Csv?: Csv;
    }
    export interface KeySchema {
      AttributeName: string;
      KeyType: string;
    }
    export interface KinesisStreamSpecification {
      StreamArn: string;
    }
    export interface LocalSecondaryIndex {
      IndexName: string;
      KeySchema: KeySchema[];
      Projection: Projection;
    }
    export interface PointInTimeRecoverySpecification {
      PointInTimeRecoveryEnabled?: boolean;
    }
    export interface Projection {
      NonKeyAttributes?: string[];
      ProjectionType?: string;
    }
    export interface ProvisionedThroughput {
      ReadCapacityUnits: number;
      WriteCapacityUnits: number;
    }
    export interface S3BucketSource {
      S3Bucket: string;
      S3BucketOwner?: string;
      S3KeyPrefix?: string;
    }
    export interface SSESpecification {
      KMSMasterKeyId?: string;
      SSEEnabled: boolean;
      SSEType?: string;
    }
    export interface StreamSpecification {
      StreamViewType: string;
    }
    export interface TimeToLiveSpecification {
      AttributeName: string;
      Enabled: boolean;
    }
  }
}
export namespace EC2 {
  export interface CapacityReservation {
    AvailabilityZone: string;
    EbsOptimized?: boolean;
    EndDate?: string;
    EndDateType?: string;
    EphemeralStorage?: boolean;
    InstanceCount: number;
    InstanceMatchCriteria?: string;
    InstancePlatform: string;
    InstanceType: string;
    OutPostArn?: string;
    PlacementGroupArn?: string;
    TagSpecifications?: CapacityReservation.TagSpecification[];
    Tenancy?: string;
  }
  export namespace CapacityReservation {
    export interface Attr {
      AvailabilityZone: string;
      AvailableInstanceCount: number;
      Id: string;
      InstanceType: string;
      Tenancy: string;
      TotalInstanceCount: number;
    }
    export interface TagSpecification {
      ResourceType?: string;
      Tags?: Tag[];
    }
  }
  export interface CapacityReservationFleet {
    AllocationStrategy?: string;
    EndDate?: string;
    InstanceMatchCriteria?: string;
    InstanceTypeSpecifications?: CapacityReservationFleet.InstanceTypeSpecification[];
    NoRemoveEndDate?: boolean;
    RemoveEndDate?: boolean;
    TagSpecifications?: CapacityReservationFleet.TagSpecification[];
    Tenancy?: string;
    TotalTargetCapacity?: number;
  }
  export namespace CapacityReservationFleet {
    export interface Attr {
      CapacityReservationFleetId: string;
    }
    export interface InstanceTypeSpecification {
      AvailabilityZone?: string;
      AvailabilityZoneId?: string;
      EbsOptimized?: boolean;
      InstancePlatform?: string;
      InstanceType?: string;
      Priority?: number;
      Weight?: number;
    }
    export interface TagSpecification {
      ResourceType?: string;
      Tags?: Tag[];
    }
  }
  export interface CarrierGateway {
    Tags?: Tag[];
    VpcId: string;
  }
  export interface ClientVpnAuthorizationRule {
    AccessGroupId?: string;
    AuthorizeAllGroups?: boolean;
    ClientVpnEndpointId: string;
    Description?: string;
    TargetNetworkCidr: string;
  }
  export interface ClientVpnEndpoint {
    AuthenticationOptions: ClientVpnEndpoint.ClientAuthenticationRequest[];
    ClientCidrBlock: string;
    ClientConnectOptions?: ClientVpnEndpoint.ClientConnectOptions;
    ClientLoginBannerOptions?: ClientVpnEndpoint.ClientLoginBannerOptions;
    ConnectionLogOptions: ClientVpnEndpoint.ConnectionLogOptions;
    Description?: string;
    DnsServers?: string[];
    SecurityGroupIds?: string[];
    SelfServicePortal?: string;
    ServerCertificateArn: string;
    SessionTimeoutHours?: number;
    SplitTunnel?: boolean;
    TagSpecifications?: ClientVpnEndpoint.TagSpecification[];
    TransportProtocol?: string;
    VpcId?: string;
    VpnPort?: number;
  }
  export namespace ClientVpnEndpoint {
    export interface Attr {}
    export interface CertificateAuthenticationRequest {
      ClientRootCertificateChainArn: string;
    }
    export interface ClientAuthenticationRequest {
      ActiveDirectory?: DirectoryServiceAuthenticationRequest;
      FederatedAuthentication?: FederatedAuthenticationRequest;
      MutualAuthentication?: CertificateAuthenticationRequest;
      Type: string;
    }
    export interface ClientConnectOptions {
      Enabled: boolean;
      LambdaFunctionArn?: string;
    }
    export interface ClientLoginBannerOptions {
      BannerText?: string;
      Enabled: boolean;
    }
    export interface ConnectionLogOptions {
      CloudwatchLogGroup?: string;
      CloudwatchLogStream?: string;
      Enabled: boolean;
    }
    export interface DirectoryServiceAuthenticationRequest {
      DirectoryId: string;
    }
    export interface FederatedAuthenticationRequest {
      SAMLProviderArn: string;
      SelfServiceSAMLProviderArn?: string;
    }
    export interface TagSpecification {
      ResourceType: string;
      Tags: Tag[];
    }
  }
  export interface ClientVpnRoute {
    ClientVpnEndpointId: string;
    Description?: string;
    DestinationCidrBlock: string;
    TargetVpcSubnetId: string;
  }
  export interface ClientVpnTargetNetworkAssociation {
    ClientVpnEndpointId: string;
    SubnetId: string;
  }
  export interface CustomerGateway {
    BgpAsn: number;
    IpAddress: string;
    Tags?: Tag[];
    Type: string;
  }
  export interface DHCPOptions {
    DomainName?: string;
    DomainNameServers?: string[];
    NetbiosNameServers?: string[];
    NetbiosNodeType?: number;
    NtpServers?: string[];
    Tags?: Tag[];
  }
  export interface EC2Fleet {
    Context?: string;
    ExcessCapacityTerminationPolicy?: string;
    LaunchTemplateConfigs: EC2Fleet.FleetLaunchTemplateConfigRequest[];
    OnDemandOptions?: EC2Fleet.OnDemandOptionsRequest;
    ReplaceUnhealthyInstances?: boolean;
    SpotOptions?: EC2Fleet.SpotOptionsRequest;
    TagSpecifications?: EC2Fleet.TagSpecification[];
    TargetCapacitySpecification: EC2Fleet.TargetCapacitySpecificationRequest;
    TerminateInstancesWithExpiration?: boolean;
    Type?: string;
    ValidFrom?: string;
    ValidUntil?: string;
  }
  export namespace EC2Fleet {
    export interface Attr {
      FleetId: string;
    }
    export interface AcceleratorCountRequest {
      Max?: number;
      Min?: number;
    }
    export interface AcceleratorTotalMemoryMiBRequest {
      Max?: number;
      Min?: number;
    }
    export interface BaselineEbsBandwidthMbpsRequest {
      Max?: number;
      Min?: number;
    }
    export interface CapacityRebalance {
      ReplacementStrategy?: string;
      TerminationDelay?: number;
    }
    export interface CapacityReservationOptionsRequest {
      UsageStrategy?: string;
    }
    export interface FleetLaunchTemplateConfigRequest {
      LaunchTemplateSpecification?: FleetLaunchTemplateSpecificationRequest;
      Overrides?: FleetLaunchTemplateOverridesRequest[];
    }
    export interface FleetLaunchTemplateOverridesRequest {
      AvailabilityZone?: string;
      InstanceRequirements?: InstanceRequirementsRequest;
      InstanceType?: string;
      MaxPrice?: string;
      Placement?: Placement;
      Priority?: number;
      SubnetId?: string;
      WeightedCapacity?: number;
    }
    export interface FleetLaunchTemplateSpecificationRequest {
      LaunchTemplateId?: string;
      LaunchTemplateName?: string;
      Version: string;
    }
    export interface InstanceRequirementsRequest {
      AcceleratorCount?: AcceleratorCountRequest;
      AcceleratorManufacturers?: string[];
      AcceleratorNames?: string[];
      AcceleratorTotalMemoryMiB?: AcceleratorTotalMemoryMiBRequest;
      AcceleratorTypes?: string[];
      AllowedInstanceTypes?: string[];
      BareMetal?: string;
      BaselineEbsBandwidthMbps?: BaselineEbsBandwidthMbpsRequest;
      BurstablePerformance?: string;
      CpuManufacturers?: string[];
      ExcludedInstanceTypes?: string[];
      InstanceGenerations?: string[];
      LocalStorage?: string;
      LocalStorageTypes?: string[];
      MemoryGiBPerVCpu?: MemoryGiBPerVCpuRequest;
      MemoryMiB?: MemoryMiBRequest;
      NetworkBandwidthGbps?: NetworkBandwidthGbpsRequest;
      NetworkInterfaceCount?: NetworkInterfaceCountRequest;
      OnDemandMaxPricePercentageOverLowestPrice?: number;
      RequireHibernateSupport?: boolean;
      SpotMaxPricePercentageOverLowestPrice?: number;
      TotalLocalStorageGB?: TotalLocalStorageGBRequest;
      VCpuCount?: VCpuCountRangeRequest;
    }
    export interface MaintenanceStrategies {
      CapacityRebalance?: CapacityRebalance;
    }
    export interface MemoryGiBPerVCpuRequest {
      Max?: number;
      Min?: number;
    }
    export interface MemoryMiBRequest {
      Max?: number;
      Min?: number;
    }
    export interface NetworkBandwidthGbpsRequest {
      Max?: number;
      Min?: number;
    }
    export interface NetworkInterfaceCountRequest {
      Max?: number;
      Min?: number;
    }
    export interface OnDemandOptionsRequest {
      AllocationStrategy?: string;
      CapacityReservationOptions?: CapacityReservationOptionsRequest;
      MaxTotalPrice?: string;
      MinTargetCapacity?: number;
      SingleAvailabilityZone?: boolean;
      SingleInstanceType?: boolean;
    }
    export interface Placement {
      Affinity?: string;
      AvailabilityZone?: string;
      GroupName?: string;
      HostId?: string;
      HostResourceGroupArn?: string;
      PartitionNumber?: number;
      SpreadDomain?: string;
      Tenancy?: string;
    }
    export interface SpotOptionsRequest {
      AllocationStrategy?: string;
      InstanceInterruptionBehavior?: string;
      InstancePoolsToUseCount?: number;
      MaintenanceStrategies?: MaintenanceStrategies;
      MaxTotalPrice?: string;
      MinTargetCapacity?: number;
      SingleAvailabilityZone?: boolean;
      SingleInstanceType?: boolean;
    }
    export interface TagSpecification {
      ResourceType?: string;
      Tags?: Tag[];
    }
    export interface TargetCapacitySpecificationRequest {
      DefaultTargetCapacityType?: string;
      OnDemandTargetCapacity?: number;
      SpotTargetCapacity?: number;
      TargetCapacityUnitType?: string;
      TotalTargetCapacity: number;
    }
    export interface TotalLocalStorageGBRequest {
      Max?: number;
      Min?: number;
    }
    export interface VCpuCountRangeRequest {
      Max?: number;
      Min?: number;
    }
  }
  export interface EIP {
    Domain?: string;
    InstanceId?: string;
    NetworkBorderGroup?: string;
    PublicIpv4Pool?: string;
    Tags?: Tag[];
    TransferAddress?: string;
  }
  export interface EIPAssociation {
    AllocationId?: string;
    EIP?: string;
    InstanceId?: string;
    NetworkInterfaceId?: string;
    PrivateIpAddress?: string;
  }
  export interface EgressOnlyInternetGateway {
    VpcId: string;
  }
  export interface EnclaveCertificateIamRoleAssociation {
    CertificateArn: string;
    RoleArn: string;
  }
  export interface FlowLog {
    DeliverLogsPermissionArn?: string;
    DestinationOptions?: any;
    LogDestination?: string;
    LogDestinationType?: string;
    LogFormat?: string;
    LogGroupName?: string;
    MaxAggregationInterval?: number;
    ResourceId: string;
    ResourceType: string;
    Tags?: Tag[];
    TrafficType?: string;
  }
  export namespace FlowLog {
    export interface Attr {
      Id: string;
    }
    export interface DestinationOptions {
      FileFormat: string;
      HiveCompatiblePartitions: boolean;
      PerHourPartition: boolean;
    }
  }
  export interface GatewayRouteTableAssociation {
    GatewayId: string;
    RouteTableId: string;
  }
  export interface Host {
    AutoPlacement?: string;
    AvailabilityZone: string;
    HostRecovery?: string;
    InstanceFamily?: string;
    InstanceType?: string;
    OutpostArn?: string;
  }
  export interface IPAM {
    Description?: string;
    OperatingRegions?: IPAM.IpamOperatingRegion[];
    Tags?: Tag[];
  }
  export namespace IPAM {
    export interface Attr {
      Arn: string;
      IpamId: string;
      PrivateDefaultScopeId: string;
      PublicDefaultScopeId: string;
      ScopeCount: number;
    }
    export interface IpamOperatingRegion {
      RegionName: string;
    }
  }
  export interface IPAMAllocation {
    Cidr?: string;
    Description?: string;
    IpamPoolId: string;
    NetmaskLength?: number;
  }
  export interface IPAMPool {
    AddressFamily: string;
    AllocationDefaultNetmaskLength?: number;
    AllocationMaxNetmaskLength?: number;
    AllocationMinNetmaskLength?: number;
    AllocationResourceTags?: Tag[];
    AutoImport?: boolean;
    AwsService?: string;
    Description?: string;
    IpamScopeId: string;
    Locale?: string;
    ProvisionedCidrs?: IPAMPool.ProvisionedCidr[];
    PubliclyAdvertisable?: boolean;
    SourceIpamPoolId?: string;
    Tags?: Tag[];
  }
  export namespace IPAMPool {
    export interface Attr {
      Arn: string;
      IpamArn: string;
      IpamPoolId: string;
      IpamScopeArn: string;
      IpamScopeType: string;
      PoolDepth: number;
      State: string;
      StateMessage: string;
    }
    export interface ProvisionedCidr {
      Cidr: string;
    }
  }
  export interface IPAMScope {
    Description?: string;
    IpamId: string;
    Tags?: Tag[];
  }
  export interface Instance {
    AdditionalInfo?: string;
    Affinity?: string;
    AvailabilityZone?: string;
    BlockDeviceMappings?: Instance.BlockDeviceMapping[];
    CpuOptions?: Instance.CpuOptions;
    CreditSpecification?: Instance.CreditSpecification;
    DisableApiTermination?: boolean;
    EbsOptimized?: boolean;
    ElasticGpuSpecifications?: Instance.ElasticGpuSpecification[];
    ElasticInferenceAccelerators?: Instance.ElasticInferenceAccelerator[];
    EnclaveOptions?: Instance.EnclaveOptions;
    HibernationOptions?: Instance.HibernationOptions;
    HostId?: string;
    HostResourceGroupArn?: string;
    IamInstanceProfile?: string;
    ImageId?: string;
    InstanceInitiatedShutdownBehavior?: string;
    InstanceType?: string;
    Ipv6AddressCount?: number;
    Ipv6Addresses?: Instance.InstanceIpv6Address[];
    KernelId?: string;
    KeyName?: string;
    LaunchTemplate?: Instance.LaunchTemplateSpecification;
    LicenseSpecifications?: Instance.LicenseSpecification[];
    Monitoring?: boolean;
    NetworkInterfaces?: Instance.NetworkInterface[];
    PlacementGroupName?: string;
    PrivateDnsNameOptions?: Instance.PrivateDnsNameOptions;
    PrivateIpAddress?: string;
    PropagateTagsToVolumeOnCreation?: boolean;
    RamdiskId?: string;
    SecurityGroupIds?: string[];
    SecurityGroups?: string[];
    SourceDestCheck?: boolean;
    SsmAssociations?: Instance.SsmAssociation[];
    SubnetId?: string;
    Tags?: Tag[];
    Tenancy?: string;
    UserData?: string;
    Volumes?: Instance.Volume[];
  }
  export namespace Instance {
    export interface Attr {
      AvailabilityZone: string;
      PrivateDnsName: string;
      PrivateIp: string;
      PublicDnsName: string;
      PublicIp: string;
    }
    export interface AssociationParameter {
      Key: string;
      Value: string[];
    }
    export interface BlockDeviceMapping {
      DeviceName: string;
      Ebs?: Ebs;
      NoDevice?: NoDevice;
      VirtualName?: string;
    }
    export interface CpuOptions {
      CoreCount?: number;
      ThreadsPerCore?: number;
    }
    export interface CreditSpecification {
      CPUCredits?: string;
    }
    export interface Ebs {
      DeleteOnTermination?: boolean;
      Encrypted?: boolean;
      Iops?: number;
      KmsKeyId?: string;
      SnapshotId?: string;
      VolumeSize?: number;
      VolumeType?: string;
    }
    export interface ElasticGpuSpecification {
      Type: string;
    }
    export interface ElasticInferenceAccelerator {
      Count?: number;
      Type: string;
    }
    export interface EnclaveOptions {
      Enabled?: boolean;
    }
    export interface HibernationOptions {
      Configured?: boolean;
    }
    export interface InstanceIpv6Address {
      Ipv6Address: string;
    }
    export interface LaunchTemplateSpecification {
      LaunchTemplateId?: string;
      LaunchTemplateName?: string;
      Version: string;
    }
    export interface LicenseSpecification {
      LicenseConfigurationArn: string;
    }
    export interface NetworkInterface {
      AssociateCarrierIpAddress?: boolean;
      AssociatePublicIpAddress?: boolean;
      DeleteOnTermination?: boolean;
      Description?: string;
      DeviceIndex: string;
      GroupSet?: string[];
      Ipv6AddressCount?: number;
      Ipv6Addresses?: InstanceIpv6Address[];
      NetworkInterfaceId?: string;
      PrivateIpAddress?: string;
      PrivateIpAddresses?: PrivateIpAddressSpecification[];
      SecondaryPrivateIpAddressCount?: number;
      SubnetId?: string;
    }
    export interface NoDevice {}
    export interface PrivateDnsNameOptions {
      EnableResourceNameDnsAAAARecord?: boolean;
      EnableResourceNameDnsARecord?: boolean;
      HostnameType?: string;
    }
    export interface PrivateIpAddressSpecification {
      Primary: boolean;
      PrivateIpAddress: string;
    }
    export interface SsmAssociation {
      AssociationParameters?: AssociationParameter[];
      DocumentName: string;
    }
    export interface Volume {
      Device: string;
      VolumeId: string;
    }
  }
  export interface InternetGateway {
    Tags?: Tag[];
  }
  export interface KeyPair {
    KeyName: string;
    KeyType?: string;
    PublicKeyMaterial?: string;
    Tags?: Tag[];
  }
  export interface LaunchTemplate {
    LaunchTemplateData: LaunchTemplate.LaunchTemplateData;
    LaunchTemplateName?: string;
    TagSpecifications?: LaunchTemplate.LaunchTemplateTagSpecification[];
    VersionDescription?: string;
  }
  export namespace LaunchTemplate {
    export interface Attr {
      DefaultVersionNumber: string;
      LatestVersionNumber: string;
    }
    export interface AcceleratorCount {
      Max?: number;
      Min?: number;
    }
    export interface AcceleratorTotalMemoryMiB {
      Max?: number;
      Min?: number;
    }
    export interface BaselineEbsBandwidthMbps {
      Max?: number;
      Min?: number;
    }
    export interface BlockDeviceMapping {
      DeviceName?: string;
      Ebs?: Ebs;
      NoDevice?: string;
      VirtualName?: string;
    }
    export interface CapacityReservationSpecification {
      CapacityReservationPreference?: string;
      CapacityReservationTarget?: CapacityReservationTarget;
    }
    export interface CapacityReservationTarget {
      CapacityReservationId?: string;
      CapacityReservationResourceGroupArn?: string;
    }
    export interface CpuOptions {
      CoreCount?: number;
      ThreadsPerCore?: number;
    }
    export interface CreditSpecification {
      CpuCredits?: string;
    }
    export interface Ebs {
      DeleteOnTermination?: boolean;
      Encrypted?: boolean;
      Iops?: number;
      KmsKeyId?: string;
      SnapshotId?: string;
      Throughput?: number;
      VolumeSize?: number;
      VolumeType?: string;
    }
    export interface ElasticGpuSpecification {
      Type?: string;
    }
    export interface EnclaveOptions {
      Enabled?: boolean;
    }
    export interface HibernationOptions {
      Configured?: boolean;
    }
    export interface IamInstanceProfile {
      Arn?: string;
      Name?: string;
    }
    export interface InstanceMarketOptions {
      MarketType?: string;
      SpotOptions?: SpotOptions;
    }
    export interface InstanceRequirements {
      AcceleratorCount?: AcceleratorCount;
      AcceleratorManufacturers?: string[];
      AcceleratorNames?: string[];
      AcceleratorTotalMemoryMiB?: AcceleratorTotalMemoryMiB;
      AcceleratorTypes?: string[];
      AllowedInstanceTypes?: string[];
      BareMetal?: string;
      BaselineEbsBandwidthMbps?: BaselineEbsBandwidthMbps;
      BurstablePerformance?: string;
      CpuManufacturers?: string[];
      ExcludedInstanceTypes?: string[];
      InstanceGenerations?: string[];
      LocalStorage?: string;
      LocalStorageTypes?: string[];
      MemoryGiBPerVCpu?: MemoryGiBPerVCpu;
      MemoryMiB?: MemoryMiB;
      NetworkBandwidthGbps?: NetworkBandwidthGbps;
      NetworkInterfaceCount?: NetworkInterfaceCount;
      OnDemandMaxPricePercentageOverLowestPrice?: number;
      RequireHibernateSupport?: boolean;
      SpotMaxPricePercentageOverLowestPrice?: number;
      TotalLocalStorageGB?: TotalLocalStorageGB;
      VCpuCount?: VCpuCount;
    }
    export interface Ipv4PrefixSpecification {
      Ipv4Prefix?: string;
    }
    export interface Ipv6Add {
      Ipv6Address?: string;
    }
    export interface Ipv6PrefixSpecification {
      Ipv6Prefix?: string;
    }
    export interface LaunchTemplateData {
      BlockDeviceMappings?: BlockDeviceMapping[];
      CapacityReservationSpecification?: CapacityReservationSpecification;
      CpuOptions?: CpuOptions;
      CreditSpecification?: CreditSpecification;
      DisableApiStop?: boolean;
      DisableApiTermination?: boolean;
      EbsOptimized?: boolean;
      ElasticGpuSpecifications?: ElasticGpuSpecification[];
      ElasticInferenceAccelerators?: LaunchTemplateElasticInferenceAccelerator[];
      EnclaveOptions?: EnclaveOptions;
      HibernationOptions?: HibernationOptions;
      IamInstanceProfile?: IamInstanceProfile;
      ImageId?: string;
      InstanceInitiatedShutdownBehavior?: string;
      InstanceMarketOptions?: InstanceMarketOptions;
      InstanceRequirements?: InstanceRequirements;
      InstanceType?: string;
      KernelId?: string;
      KeyName?: string;
      LicenseSpecifications?: LicenseSpecification[];
      MaintenanceOptions?: MaintenanceOptions;
      MetadataOptions?: MetadataOptions;
      Monitoring?: Monitoring;
      NetworkInterfaces?: NetworkInterface[];
      Placement?: Placement;
      PrivateDnsNameOptions?: PrivateDnsNameOptions;
      RamDiskId?: string;
      SecurityGroupIds?: string[];
      SecurityGroups?: string[];
      TagSpecifications?: TagSpecification[];
      UserData?: string;
    }
    export interface LaunchTemplateElasticInferenceAccelerator {
      Count?: number;
      Type?: string;
    }
    export interface LaunchTemplateTagSpecification {
      ResourceType?: string;
      Tags?: Tag[];
    }
    export interface LicenseSpecification {
      LicenseConfigurationArn?: string;
    }
    export interface MaintenanceOptions {
      AutoRecovery?: string;
    }
    export interface MemoryGiBPerVCpu {
      Max?: number;
      Min?: number;
    }
    export interface MemoryMiB {
      Max?: number;
      Min?: number;
    }
    export interface MetadataOptions {
      HttpEndpoint?: string;
      HttpProtocolIpv6?: string;
      HttpPutResponseHopLimit?: number;
      HttpTokens?: string;
      InstanceMetadataTags?: string;
    }
    export interface Monitoring {
      Enabled?: boolean;
    }
    export interface NetworkBandwidthGbps {
      Max?: number;
      Min?: number;
    }
    export interface NetworkInterface {
      AssociateCarrierIpAddress?: boolean;
      AssociatePublicIpAddress?: boolean;
      DeleteOnTermination?: boolean;
      Description?: string;
      DeviceIndex?: number;
      Groups?: string[];
      InterfaceType?: string;
      Ipv4PrefixCount?: number;
      Ipv4Prefixes?: Ipv4PrefixSpecification[];
      Ipv6AddressCount?: number;
      Ipv6Addresses?: Ipv6Add[];
      Ipv6PrefixCount?: number;
      Ipv6Prefixes?: Ipv6PrefixSpecification[];
      NetworkCardIndex?: number;
      NetworkInterfaceId?: string;
      PrivateIpAddress?: string;
      PrivateIpAddresses?: PrivateIpAdd[];
      SecondaryPrivateIpAddressCount?: number;
      SubnetId?: string;
    }
    export interface NetworkInterfaceCount {
      Max?: number;
      Min?: number;
    }
    export interface Placement {
      Affinity?: string;
      AvailabilityZone?: string;
      GroupId?: string;
      GroupName?: string;
      HostId?: string;
      HostResourceGroupArn?: string;
      PartitionNumber?: number;
      SpreadDomain?: string;
      Tenancy?: string;
    }
    export interface PrivateDnsNameOptions {
      EnableResourceNameDnsAAAARecord?: boolean;
      EnableResourceNameDnsARecord?: boolean;
      HostnameType?: string;
    }
    export interface PrivateIpAdd {
      Primary?: boolean;
      PrivateIpAddress?: string;
    }
    export interface SpotOptions {
      BlockDurationMinutes?: number;
      InstanceInterruptionBehavior?: string;
      MaxPrice?: string;
      SpotInstanceType?: string;
      ValidUntil?: string;
    }
    export interface TagSpecification {
      ResourceType?: string;
      Tags?: Tag[];
    }
    export interface TotalLocalStorageGB {
      Max?: number;
      Min?: number;
    }
    export interface VCpuCount {
      Max?: number;
      Min?: number;
    }
  }
  export interface LocalGatewayRoute {
    DestinationCidrBlock: string;
    LocalGatewayRouteTableId: string;
    LocalGatewayVirtualInterfaceGroupId?: string;
    NetworkInterfaceId?: string;
  }
  export interface LocalGatewayRouteTableVPCAssociation {
    LocalGatewayRouteTableId: string;
    Tags?: Tag[];
    VpcId: string;
  }
  export interface NatGateway {
    AllocationId?: string;
    ConnectivityType?: string;
    PrivateIpAddress?: string;
    SubnetId: string;
    Tags?: Tag[];
  }
  export interface NetworkAcl {
    Tags?: Tag[];
    VpcId: string;
  }
  export interface NetworkAclEntry {
    CidrBlock?: string;
    Egress?: boolean;
    Icmp?: NetworkAclEntry.Icmp;
    Ipv6CidrBlock?: string;
    NetworkAclId: string;
    PortRange?: NetworkAclEntry.PortRange;
    Protocol: number;
    RuleAction: string;
    RuleNumber: number;
  }
  export namespace NetworkAclEntry {
    export interface Attr {
      Id: string;
    }
    export interface Icmp {
      Code?: number;
      Type?: number;
    }
    export interface PortRange {
      From?: number;
      To?: number;
    }
  }
  export interface NetworkInsightsAccessScope {
    ExcludePaths?: NetworkInsightsAccessScope.AccessScopePathRequest[];
    MatchPaths?: NetworkInsightsAccessScope.AccessScopePathRequest[];
    Tags?: Tag[];
  }
  export namespace NetworkInsightsAccessScope {
    export interface Attr {
      CreatedDate: string;
      NetworkInsightsAccessScopeArn: string;
      NetworkInsightsAccessScopeId: string;
      UpdatedDate: string;
    }
    export interface AccessScopePathRequest {
      Destination?: PathStatementRequest;
      Source?: PathStatementRequest;
      ThroughResources?: ThroughResourcesStatementRequest[];
    }
    export interface PacketHeaderStatementRequest {
      DestinationAddresses?: string[];
      DestinationPorts?: string[];
      DestinationPrefixLists?: string[];
      Protocols?: string[];
      SourceAddresses?: string[];
      SourcePorts?: string[];
      SourcePrefixLists?: string[];
    }
    export interface PathStatementRequest {
      PacketHeaderStatement?: PacketHeaderStatementRequest;
      ResourceStatement?: ResourceStatementRequest;
    }
    export interface ResourceStatementRequest {
      ResourceTypes?: string[];
      Resources?: string[];
    }
    export interface ThroughResourcesStatementRequest {
      ResourceStatement?: ResourceStatementRequest;
    }
  }
  export interface NetworkInsightsAccessScopeAnalysis {
    NetworkInsightsAccessScopeId: string;
    Tags?: Tag[];
  }
  export interface NetworkInsightsAnalysis {
    AdditionalAccounts?: string[];
    FilterInArns?: string[];
    NetworkInsightsPathId: string;
    Tags?: Tag[];
  }
  export namespace NetworkInsightsAnalysis {
    export interface Attr {
      AlternatePathHints: AlternatePathHint[];
      Explanations: Explanation[];
      ForwardPathComponents: PathComponent[];
      NetworkInsightsAnalysisArn: string;
      NetworkInsightsAnalysisId: string;
      NetworkPathFound: boolean;
      ReturnPathComponents: PathComponent[];
      StartDate: string;
      Status: string;
      StatusMessage: string;
      SuggestedAccounts: string[];
    }
    export interface AdditionalDetail {
      AdditionalDetailType?: string;
      Component?: AnalysisComponent;
    }
    export interface AlternatePathHint {
      ComponentArn?: string;
      ComponentId?: string;
    }
    export interface AnalysisAclRule {
      Cidr?: string;
      Egress?: boolean;
      PortRange?: PortRange;
      Protocol?: string;
      RuleAction?: string;
      RuleNumber?: number;
    }
    export interface AnalysisComponent {
      Arn?: string;
      Id?: string;
    }
    export interface AnalysisLoadBalancerListener {
      InstancePort?: number;
      LoadBalancerPort?: number;
    }
    export interface AnalysisLoadBalancerTarget {
      Address?: string;
      AvailabilityZone?: string;
      Instance?: AnalysisComponent;
      Port?: number;
    }
    export interface AnalysisPacketHeader {
      DestinationAddresses?: string[];
      DestinationPortRanges?: PortRange[];
      Protocol?: string;
      SourceAddresses?: string[];
      SourcePortRanges?: PortRange[];
    }
    export interface AnalysisRouteTableRoute {
      NatGatewayId?: string;
      NetworkInterfaceId?: string;
      Origin?: string;
      State?: string;
      TransitGatewayId?: string;
      VpcPeeringConnectionId?: string;
      destinationCidr?: string;
      destinationPrefixListId?: string;
      egressOnlyInternetGatewayId?: string;
      gatewayId?: string;
      instanceId?: string;
    }
    export interface AnalysisSecurityGroupRule {
      Cidr?: string;
      Direction?: string;
      PortRange?: PortRange;
      PrefixListId?: string;
      Protocol?: string;
      SecurityGroupId?: string;
    }
    export interface Explanation {
      Acl?: AnalysisComponent;
      AclRule?: AnalysisAclRule;
      Address?: string;
      Addresses?: string[];
      AttachedTo?: AnalysisComponent;
      AvailabilityZones?: string[];
      Cidrs?: string[];
      ClassicLoadBalancerListener?: AnalysisLoadBalancerListener;
      Component?: AnalysisComponent;
      ComponentAccount?: string;
      ComponentRegion?: string;
      CustomerGateway?: AnalysisComponent;
      Destination?: AnalysisComponent;
      DestinationVpc?: AnalysisComponent;
      Direction?: string;
      ElasticLoadBalancerListener?: AnalysisComponent;
      ExplanationCode?: string;
      IngressRouteTable?: AnalysisComponent;
      InternetGateway?: AnalysisComponent;
      LoadBalancerArn?: string;
      LoadBalancerListenerPort?: number;
      LoadBalancerTarget?: AnalysisLoadBalancerTarget;
      LoadBalancerTargetGroup?: AnalysisComponent;
      LoadBalancerTargetGroups?: AnalysisComponent[];
      LoadBalancerTargetPort?: number;
      MissingComponent?: string;
      NatGateway?: AnalysisComponent;
      NetworkInterface?: AnalysisComponent;
      PacketField?: string;
      Port?: number;
      PortRanges?: PortRange[];
      PrefixList?: AnalysisComponent;
      Protocols?: string[];
      RouteTable?: AnalysisComponent;
      RouteTableRoute?: AnalysisRouteTableRoute;
      SecurityGroup?: AnalysisComponent;
      SecurityGroupRule?: AnalysisSecurityGroupRule;
      SecurityGroups?: AnalysisComponent[];
      SourceVpc?: AnalysisComponent;
      State?: string;
      Subnet?: AnalysisComponent;
      SubnetRouteTable?: AnalysisComponent;
      TransitGateway?: AnalysisComponent;
      TransitGatewayAttachment?: AnalysisComponent;
      TransitGatewayRouteTable?: AnalysisComponent;
      TransitGatewayRouteTableRoute?: TransitGatewayRouteTableRoute;
      Vpc?: AnalysisComponent;
      VpcPeeringConnection?: AnalysisComponent;
      VpnConnection?: AnalysisComponent;
      VpnGateway?: AnalysisComponent;
      vpcEndpoint?: AnalysisComponent;
    }
    export interface PathComponent {
      AclRule?: AnalysisAclRule;
      AdditionalDetails?: AdditionalDetail[];
      Component?: AnalysisComponent;
      DestinationVpc?: AnalysisComponent;
      ElasticLoadBalancerListener?: AnalysisComponent;
      Explanations?: Explanation[];
      InboundHeader?: AnalysisPacketHeader;
      OutboundHeader?: AnalysisPacketHeader;
      RouteTableRoute?: AnalysisRouteTableRoute;
      SecurityGroupRule?: AnalysisSecurityGroupRule;
      SequenceNumber?: number;
      SourceVpc?: AnalysisComponent;
      Subnet?: AnalysisComponent;
      TransitGateway?: AnalysisComponent;
      TransitGatewayRouteTableRoute?: TransitGatewayRouteTableRoute;
      Vpc?: AnalysisComponent;
    }
    export interface PortRange {
      From?: number;
      To?: number;
    }
    export interface TransitGatewayRouteTableRoute {
      AttachmentId?: string;
      DestinationCidr?: string;
      PrefixListId?: string;
      ResourceId?: string;
      ResourceType?: string;
      RouteOrigin?: string;
      State?: string;
    }
  }
  export interface NetworkInsightsPath {
    Destination: string;
    DestinationIp?: string;
    DestinationPort?: number;
    Protocol: string;
    Source: string;
    SourceIp?: string;
    Tags?: Tag[];
  }
  export interface NetworkInterface {
    Description?: string;
    GroupSet?: string[];
    InterfaceType?: string;
    Ipv6AddressCount?: number;
    Ipv6Addresses?: NetworkInterface.InstanceIpv6Address[];
    PrivateIpAddress?: string;
    PrivateIpAddresses?: NetworkInterface.PrivateIpAddressSpecification[];
    SecondaryPrivateIpAddressCount?: number;
    SourceDestCheck?: boolean;
    SubnetId: string;
    Tags?: Tag[];
  }
  export namespace NetworkInterface {
    export interface Attr {
      Id: string;
      PrimaryPrivateIpAddress: string;
      SecondaryPrivateIpAddresses: string[];
    }
    export interface InstanceIpv6Address {
      Ipv6Address: string;
    }
    export interface PrivateIpAddressSpecification {
      Primary: boolean;
      PrivateIpAddress: string;
    }
  }
  export interface NetworkInterfaceAttachment {
    DeleteOnTermination?: boolean;
    DeviceIndex: string;
    InstanceId: string;
    NetworkInterfaceId: string;
  }
  export interface NetworkInterfacePermission {
    AwsAccountId: string;
    NetworkInterfaceId: string;
    Permission: string;
  }
  export interface NetworkPerformanceMetricSubscription {
    Destination: string;
    Metric: string;
    Source: string;
    Statistic: string;
  }
  export interface PlacementGroup {
    PartitionCount?: number;
    SpreadLevel?: string;
    Strategy?: string;
    Tags?: Tag[];
  }
  export interface PrefixList {
    AddressFamily: string;
    Entries?: PrefixList.Entry[];
    MaxEntries: number;
    PrefixListName: string;
    Tags?: Tag[];
  }
  export namespace PrefixList {
    export interface Attr {
      Arn: string;
      OwnerId: string;
      PrefixListId: string;
      Version: number;
    }
    export interface Entry {
      Cidr: string;
      Description?: string;
    }
  }
  export interface Route {
    CarrierGatewayId?: string;
    DestinationCidrBlock?: string;
    DestinationIpv6CidrBlock?: string;
    EgressOnlyInternetGatewayId?: string;
    GatewayId?: string;
    InstanceId?: string;
    LocalGatewayId?: string;
    NatGatewayId?: string;
    NetworkInterfaceId?: string;
    RouteTableId: string;
    TransitGatewayId?: string;
    VpcEndpointId?: string;
    VpcPeeringConnectionId?: string;
  }
  export interface RouteTable {
    Tags?: Tag[];
    VpcId: string;
  }
  export interface SecurityGroup {
    GroupDescription: string;
    GroupName?: string;
    SecurityGroupEgress?: SecurityGroup.Egress[];
    SecurityGroupIngress?: SecurityGroup.Ingress[];
    Tags?: Tag[];
    VpcId?: string;
  }
  export namespace SecurityGroup {
    export interface Attr {
      GroupId: string;
      VpcId: string;
    }
    export interface Egress {
      CidrIp?: string;
      CidrIpv6?: string;
      Description?: string;
      DestinationPrefixListId?: string;
      DestinationSecurityGroupId?: string;
      FromPort?: number;
      IpProtocol: string;
      ToPort?: number;
    }
    export interface Ingress {
      CidrIp?: string;
      CidrIpv6?: string;
      Description?: string;
      FromPort?: number;
      IpProtocol: string;
      SourcePrefixListId?: string;
      SourceSecurityGroupId?: string;
      SourceSecurityGroupName?: string;
      SourceSecurityGroupOwnerId?: string;
      ToPort?: number;
    }
  }
  export interface SecurityGroupEgress {
    CidrIp?: string;
    CidrIpv6?: string;
    Description?: string;
    DestinationPrefixListId?: string;
    DestinationSecurityGroupId?: string;
    FromPort?: number;
    GroupId: string;
    IpProtocol: string;
    ToPort?: number;
  }
  export interface SecurityGroupIngress {
    CidrIp?: string;
    CidrIpv6?: string;
    Description?: string;
    FromPort?: number;
    GroupId?: string;
    GroupName?: string;
    IpProtocol: string;
    SourcePrefixListId?: string;
    SourceSecurityGroupId?: string;
    SourceSecurityGroupName?: string;
    SourceSecurityGroupOwnerId?: string;
    ToPort?: number;
  }
  export interface SpotFleet {
    SpotFleetRequestConfigData: SpotFleet.SpotFleetRequestConfigData;
  }
  export namespace SpotFleet {
    export interface Attr {
      Id: string;
    }
    export interface AcceleratorCountRequest {
      Max?: number;
      Min?: number;
    }
    export interface AcceleratorTotalMemoryMiBRequest {
      Max?: number;
      Min?: number;
    }
    export interface BaselineEbsBandwidthMbpsRequest {
      Max?: number;
      Min?: number;
    }
    export interface BlockDeviceMapping {
      DeviceName: string;
      Ebs?: EbsBlockDevice;
      NoDevice?: string;
      VirtualName?: string;
    }
    export interface ClassicLoadBalancer {
      Name: string;
    }
    export interface ClassicLoadBalancersConfig {
      ClassicLoadBalancers: ClassicLoadBalancer[];
    }
    export interface EbsBlockDevice {
      DeleteOnTermination?: boolean;
      Encrypted?: boolean;
      Iops?: number;
      SnapshotId?: string;
      VolumeSize?: number;
      VolumeType?: string;
    }
    export interface FleetLaunchTemplateSpecification {
      LaunchTemplateId?: string;
      LaunchTemplateName?: string;
      Version: string;
    }
    export interface GroupIdentifier {
      GroupId: string;
    }
    export interface IamInstanceProfileSpecification {
      Arn?: string;
    }
    export interface InstanceIpv6Address {
      Ipv6Address: string;
    }
    export interface InstanceNetworkInterfaceSpecification {
      AssociatePublicIpAddress?: boolean;
      DeleteOnTermination?: boolean;
      Description?: string;
      DeviceIndex?: number;
      Groups?: string[];
      Ipv6AddressCount?: number;
      Ipv6Addresses?: InstanceIpv6Address[];
      NetworkInterfaceId?: string;
      PrivateIpAddresses?: PrivateIpAddressSpecification[];
      SecondaryPrivateIpAddressCount?: number;
      SubnetId?: string;
    }
    export interface InstanceRequirementsRequest {
      AcceleratorCount?: AcceleratorCountRequest;
      AcceleratorManufacturers?: string[];
      AcceleratorNames?: string[];
      AcceleratorTotalMemoryMiB?: AcceleratorTotalMemoryMiBRequest;
      AcceleratorTypes?: string[];
      AllowedInstanceTypes?: string[];
      BareMetal?: string;
      BaselineEbsBandwidthMbps?: BaselineEbsBandwidthMbpsRequest;
      BurstablePerformance?: string;
      CpuManufacturers?: string[];
      ExcludedInstanceTypes?: string[];
      InstanceGenerations?: string[];
      LocalStorage?: string;
      LocalStorageTypes?: string[];
      MemoryGiBPerVCpu?: MemoryGiBPerVCpuRequest;
      MemoryMiB?: MemoryMiBRequest;
      NetworkBandwidthGbps?: NetworkBandwidthGbpsRequest;
      NetworkInterfaceCount?: NetworkInterfaceCountRequest;
      OnDemandMaxPricePercentageOverLowestPrice?: number;
      RequireHibernateSupport?: boolean;
      SpotMaxPricePercentageOverLowestPrice?: number;
      TotalLocalStorageGB?: TotalLocalStorageGBRequest;
      VCpuCount?: VCpuCountRangeRequest;
    }
    export interface LaunchTemplateConfig {
      LaunchTemplateSpecification?: FleetLaunchTemplateSpecification;
      Overrides?: LaunchTemplateOverrides[];
    }
    export interface LaunchTemplateOverrides {
      AvailabilityZone?: string;
      InstanceRequirements?: InstanceRequirementsRequest;
      InstanceType?: string;
      Priority?: number;
      SpotPrice?: string;
      SubnetId?: string;
      WeightedCapacity?: number;
    }
    export interface LoadBalancersConfig {
      ClassicLoadBalancersConfig?: ClassicLoadBalancersConfig;
      TargetGroupsConfig?: TargetGroupsConfig;
    }
    export interface MemoryGiBPerVCpuRequest {
      Max?: number;
      Min?: number;
    }
    export interface MemoryMiBRequest {
      Max?: number;
      Min?: number;
    }
    export interface NetworkBandwidthGbpsRequest {
      Max?: number;
      Min?: number;
    }
    export interface NetworkInterfaceCountRequest {
      Max?: number;
      Min?: number;
    }
    export interface PrivateIpAddressSpecification {
      Primary?: boolean;
      PrivateIpAddress: string;
    }
    export interface SpotCapacityRebalance {
      ReplacementStrategy?: string;
      TerminationDelay?: number;
    }
    export interface SpotFleetLaunchSpecification {
      BlockDeviceMappings?: BlockDeviceMapping[];
      EbsOptimized?: boolean;
      IamInstanceProfile?: IamInstanceProfileSpecification;
      ImageId: string;
      InstanceRequirements?: InstanceRequirementsRequest;
      InstanceType?: string;
      KernelId?: string;
      KeyName?: string;
      Monitoring?: SpotFleetMonitoring;
      NetworkInterfaces?: InstanceNetworkInterfaceSpecification[];
      Placement?: SpotPlacement;
      RamdiskId?: string;
      SecurityGroups?: GroupIdentifier[];
      SpotPrice?: string;
      SubnetId?: string;
      TagSpecifications?: SpotFleetTagSpecification[];
      UserData?: string;
      WeightedCapacity?: number;
    }
    export interface SpotFleetMonitoring {
      Enabled?: boolean;
    }
    export interface SpotFleetRequestConfigData {
      AllocationStrategy?: string;
      Context?: string;
      ExcessCapacityTerminationPolicy?: string;
      IamFleetRole: string;
      InstanceInterruptionBehavior?: string;
      InstancePoolsToUseCount?: number;
      LaunchSpecifications?: SpotFleetLaunchSpecification[];
      LaunchTemplateConfigs?: LaunchTemplateConfig[];
      LoadBalancersConfig?: LoadBalancersConfig;
      OnDemandAllocationStrategy?: string;
      OnDemandMaxTotalPrice?: string;
      OnDemandTargetCapacity?: number;
      ReplaceUnhealthyInstances?: boolean;
      SpotMaintenanceStrategies?: SpotMaintenanceStrategies;
      SpotMaxTotalPrice?: string;
      SpotPrice?: string;
      TagSpecifications?: SpotFleetTagSpecification[];
      TargetCapacity: number;
      TargetCapacityUnitType?: string;
      TerminateInstancesWithExpiration?: boolean;
      Type?: string;
      ValidFrom?: string;
      ValidUntil?: string;
    }
    export interface SpotFleetTagSpecification {
      ResourceType?: string;
      Tags?: Tag[];
    }
    export interface SpotMaintenanceStrategies {
      CapacityRebalance?: SpotCapacityRebalance;
    }
    export interface SpotPlacement {
      AvailabilityZone?: string;
      GroupName?: string;
      Tenancy?: string;
    }
    export interface TargetGroup {
      Arn: string;
    }
    export interface TargetGroupsConfig {
      TargetGroups: TargetGroup[];
    }
    export interface TotalLocalStorageGBRequest {
      Max?: number;
      Min?: number;
    }
    export interface VCpuCountRangeRequest {
      Max?: number;
      Min?: number;
    }
  }
  export interface Subnet {
    AssignIpv6AddressOnCreation?: boolean;
    AvailabilityZone?: string;
    AvailabilityZoneId?: string;
    CidrBlock?: string;
    EnableDns64?: boolean;
    Ipv6CidrBlock?: string;
    Ipv6Native?: boolean;
    MapPublicIpOnLaunch?: boolean;
    OutpostArn?: string;
    PrivateDnsNameOptionsOnLaunch?: any;
    Tags?: Tag[];
    VpcId: string;
  }
  export namespace Subnet {
    export interface Attr {
      AvailabilityZone: string;
      Ipv6CidrBlocks: string[];
      NetworkAclAssociationId: string;
      OutpostArn: string;
      SubnetId: string;
      VpcId: string;
    }
    export interface PrivateDnsNameOptionsOnLaunch {
      EnableResourceNameDnsAAAARecord?: boolean;
      EnableResourceNameDnsARecord?: boolean;
      HostnameType?: string;
    }
  }
  export interface SubnetCidrBlock {
    Ipv6CidrBlock: string;
    SubnetId: string;
  }
  export interface SubnetNetworkAclAssociation {
    NetworkAclId: string;
    SubnetId: string;
  }
  export interface SubnetRouteTableAssociation {
    RouteTableId: string;
    SubnetId: string;
  }
  export interface TrafficMirrorFilter {
    Description?: string;
    NetworkServices?: string[];
    Tags?: Tag[];
  }
  export interface TrafficMirrorFilterRule {
    Description?: string;
    DestinationCidrBlock: string;
    DestinationPortRange?: TrafficMirrorFilterRule.TrafficMirrorPortRange;
    Protocol?: number;
    RuleAction: string;
    RuleNumber: number;
    SourceCidrBlock: string;
    SourcePortRange?: TrafficMirrorFilterRule.TrafficMirrorPortRange;
    TrafficDirection: string;
    TrafficMirrorFilterId: string;
  }
  export namespace TrafficMirrorFilterRule {
    export interface Attr {}
    export interface TrafficMirrorPortRange {
      FromPort: number;
      ToPort: number;
    }
  }
  export interface TrafficMirrorSession {
    Description?: string;
    NetworkInterfaceId: string;
    PacketLength?: number;
    SessionNumber: number;
    Tags?: Tag[];
    TrafficMirrorFilterId: string;
    TrafficMirrorTargetId: string;
    VirtualNetworkId?: number;
  }
  export interface TrafficMirrorTarget {
    Description?: string;
    GatewayLoadBalancerEndpointId?: string;
    NetworkInterfaceId?: string;
    NetworkLoadBalancerArn?: string;
    Tags?: Tag[];
  }
  export interface TransitGateway {
    AmazonSideAsn?: number;
    AssociationDefaultRouteTableId?: string;
    AutoAcceptSharedAttachments?: string;
    DefaultRouteTableAssociation?: string;
    DefaultRouteTablePropagation?: string;
    Description?: string;
    DnsSupport?: string;
    MulticastSupport?: string;
    PropagationDefaultRouteTableId?: string;
    Tags?: Tag[];
    TransitGatewayCidrBlocks?: string[];
    VpnEcmpSupport?: string;
  }
  export interface TransitGatewayAttachment {
    Options?: any;
    SubnetIds: string[];
    Tags?: Tag[];
    TransitGatewayId: string;
    VpcId: string;
  }
  export namespace TransitGatewayAttachment {
    export interface Attr {
      Id: string;
    }
    export interface Options {
      ApplianceModeSupport?: string;
      DnsSupport?: string;
      Ipv6Support?: string;
    }
  }
  export interface TransitGatewayConnect {
    Options: TransitGatewayConnect.TransitGatewayConnectOptions;
    Tags?: Tag[];
    TransportTransitGatewayAttachmentId: string;
  }
  export namespace TransitGatewayConnect {
    export interface Attr {
      CreationTime: string;
      State: string;
      TransitGatewayAttachmentId: string;
      TransitGatewayId: string;
    }
    export interface TransitGatewayConnectOptions {
      Protocol?: string;
    }
  }
  export interface TransitGatewayMulticastDomain {
    Options?: any;
    Tags?: Tag[];
    TransitGatewayId: string;
  }
  export namespace TransitGatewayMulticastDomain {
    export interface Attr {
      CreationTime: string;
      State: string;
      TransitGatewayMulticastDomainArn: string;
      TransitGatewayMulticastDomainId: string;
    }
    export interface Options {
      AutoAcceptSharedAssociations?: string;
      Igmpv2Support?: string;
      StaticSourcesSupport?: string;
    }
  }
  export interface TransitGatewayMulticastDomainAssociation {
    SubnetId: string;
    TransitGatewayAttachmentId: string;
    TransitGatewayMulticastDomainId: string;
  }
  export interface TransitGatewayMulticastGroupMember {
    GroupIpAddress: string;
    NetworkInterfaceId: string;
    TransitGatewayMulticastDomainId: string;
  }
  export interface TransitGatewayMulticastGroupSource {
    GroupIpAddress: string;
    NetworkInterfaceId: string;
    TransitGatewayMulticastDomainId: string;
  }
  export interface TransitGatewayPeeringAttachment {
    PeerAccountId: string;
    PeerRegion: string;
    PeerTransitGatewayId: string;
    Tags?: Tag[];
    TransitGatewayId: string;
  }
  export namespace TransitGatewayPeeringAttachment {
    export interface Attr {
      CreationTime: string;
      State: string;
      "Status.Code": string;
      "Status.Message": string;
      TransitGatewayAttachmentId: string;
    }
    export interface PeeringAttachmentStatus {
      Code?: string;
      Message?: string;
    }
  }
  export interface TransitGatewayRoute {
    Blackhole?: boolean;
    DestinationCidrBlock?: string;
    TransitGatewayAttachmentId?: string;
    TransitGatewayRouteTableId: string;
  }
  export interface TransitGatewayRouteTable {
    Tags?: Tag[];
    TransitGatewayId: string;
  }
  export interface TransitGatewayRouteTableAssociation {
    TransitGatewayAttachmentId: string;
    TransitGatewayRouteTableId: string;
  }
  export interface TransitGatewayRouteTablePropagation {
    TransitGatewayAttachmentId: string;
    TransitGatewayRouteTableId: string;
  }
  export interface TransitGatewayVpcAttachment {
    AddSubnetIds?: string[];
    Options?: any;
    RemoveSubnetIds?: string[];
    SubnetIds: string[];
    Tags?: Tag[];
    TransitGatewayId: string;
    VpcId: string;
  }
  export namespace TransitGatewayVpcAttachment {
    export interface Attr {
      Id: string;
    }
    export interface Options {
      ApplianceModeSupport?: string;
      DnsSupport?: string;
      Ipv6Support?: string;
    }
  }
  export interface VPC {
    CidrBlock?: string;
    EnableDnsHostnames?: boolean;
    EnableDnsSupport?: boolean;
    InstanceTenancy?: string;
    Ipv4IpamPoolId?: string;
    Ipv4NetmaskLength?: number;
    Tags?: Tag[];
  }
  export interface VPCCidrBlock {
    AmazonProvidedIpv6CidrBlock?: boolean;
    CidrBlock?: string;
    Ipv4IpamPoolId?: string;
    Ipv4NetmaskLength?: number;
    Ipv6CidrBlock?: string;
    Ipv6IpamPoolId?: string;
    Ipv6NetmaskLength?: number;
    Ipv6Pool?: string;
    VpcId: string;
  }
  export interface VPCDHCPOptionsAssociation {
    DhcpOptionsId: string;
    VpcId: string;
  }
  export interface VPCEndpoint {
    PolicyDocument?: any;
    PrivateDnsEnabled?: boolean;
    RouteTableIds?: string[];
    SecurityGroupIds?: string[];
    ServiceName: string;
    SubnetIds?: string[];
    VpcEndpointType?: string;
    VpcId: string;
  }
  export interface VPCEndpointConnectionNotification {
    ConnectionEvents: string[];
    ConnectionNotificationArn: string;
    ServiceId?: string;
    VPCEndpointId?: string;
  }
  export interface VPCEndpointService {
    AcceptanceRequired?: boolean;
    ContributorInsightsEnabled?: boolean;
    GatewayLoadBalancerArns?: string[];
    NetworkLoadBalancerArns?: string[];
    PayerResponsibility?: string;
  }
  export interface VPCEndpointServicePermissions {
    AllowedPrincipals?: string[];
    ServiceId: string;
  }
  export interface VPCGatewayAttachment {
    InternetGatewayId?: string;
    VpcId: string;
    VpnGatewayId?: string;
  }
  export interface VPCPeeringConnection {
    PeerOwnerId?: string;
    PeerRegion?: string;
    PeerRoleArn?: string;
    PeerVpcId: string;
    Tags?: Tag[];
    VpcId: string;
  }
  export interface VPNConnection {
    CustomerGatewayId: string;
    StaticRoutesOnly?: boolean;
    Tags?: Tag[];
    TransitGatewayId?: string;
    Type: string;
    VpnGatewayId?: string;
    VpnTunnelOptionsSpecifications?: VPNConnection.VpnTunnelOptionsSpecification[];
  }
  export namespace VPNConnection {
    export interface Attr {
      VpnConnectionId: string;
    }
    export interface VpnTunnelOptionsSpecification {
      PreSharedKey?: string;
      TunnelInsideCidr?: string;
    }
  }
  export interface VPNConnectionRoute {
    DestinationCidrBlock: string;
    VpnConnectionId: string;
  }
  export interface VPNGateway {
    AmazonSideAsn?: number;
    Tags?: Tag[];
    Type: string;
  }
  export interface VPNGatewayRoutePropagation {
    RouteTableIds: string[];
    VpnGatewayId: string;
  }
  export interface Volume {
    AutoEnableIO?: boolean;
    AvailabilityZone: string;
    Encrypted?: boolean;
    Iops?: number;
    KmsKeyId?: string;
    MultiAttachEnabled?: boolean;
    OutpostArn?: string;
    Size?: number;
    SnapshotId?: string;
    Tags?: Tag[];
    Throughput?: number;
    VolumeType?: string;
  }
  export interface VolumeAttachment {
    Device: string;
    InstanceId: string;
    VolumeId: string;
  }
}
export namespace ECR {
  export interface PublicRepository {
    RepositoryCatalogData?: any;
    RepositoryName?: string;
    RepositoryPolicyText?: any;
    Tags?: Tag[];
  }
  export namespace PublicRepository {
    export interface Attr {
      Arn: string;
    }
    export interface RepositoryCatalogData {
      AboutText?: string;
      Architectures?: string[];
      OperatingSystems?: string[];
      RepositoryDescription?: string;
      UsageText?: string;
    }
  }
  export interface PullThroughCacheRule {
    EcrRepositoryPrefix?: string;
    UpstreamRegistryUrl?: string;
  }
  export interface RegistryPolicy {
    PolicyText: any;
  }
  export interface ReplicationConfiguration {
    ReplicationConfiguration: ReplicationConfiguration.ReplicationConfiguration;
  }
  export namespace ReplicationConfiguration {
    export interface Attr {
      RegistryId: string;
    }
    export interface ReplicationConfiguration {
      Rules: ReplicationRule[];
    }
    export interface ReplicationDestination {
      Region: string;
      RegistryId: string;
    }
    export interface ReplicationRule {
      Destinations: ReplicationDestination[];
      RepositoryFilters?: RepositoryFilter[];
    }
    export interface RepositoryFilter {
      Filter: string;
      FilterType: string;
    }
  }
  export interface Repository {
    EncryptionConfiguration?: Repository.EncryptionConfiguration;
    ImageScanningConfiguration?: Repository.ImageScanningConfiguration;
    ImageTagMutability?: string;
    LifecyclePolicy?: Repository.LifecyclePolicy;
    RepositoryName?: string;
    RepositoryPolicyText?: any;
    Tags?: Tag[];
  }
  export namespace Repository {
    export interface Attr {
      Arn: string;
      RepositoryUri: string;
    }
    export interface EncryptionConfiguration {
      EncryptionType: string;
      KmsKey?: string;
    }
    export interface ImageScanningConfiguration {
      ScanOnPush?: boolean;
    }
    export interface LifecyclePolicy {
      LifecyclePolicyText?: string;
      RegistryId?: string;
    }
  }
}
export namespace ECS {
  export interface CapacityProvider {
    AutoScalingGroupProvider: CapacityProvider.AutoScalingGroupProvider;
    Name?: string;
    Tags?: Tag[];
  }
  export namespace CapacityProvider {
    export interface Attr {}
    export interface AutoScalingGroupProvider {
      AutoScalingGroupArn: string;
      ManagedScaling?: ManagedScaling;
      ManagedTerminationProtection?: string;
    }
    export interface ManagedScaling {
      InstanceWarmupPeriod?: number;
      MaximumScalingStepSize?: number;
      MinimumScalingStepSize?: number;
      Status?: string;
      TargetCapacity?: number;
    }
  }
  export interface Cluster {
    CapacityProviders?: string[];
    ClusterName?: string;
    ClusterSettings?: Cluster.ClusterSettings[];
    Configuration?: Cluster.ClusterConfiguration;
    DefaultCapacityProviderStrategy?: Cluster.CapacityProviderStrategyItem[];
    ServiceConnectDefaults?: Cluster.ServiceConnectDefaults;
    Tags?: Tag[];
  }
  export namespace Cluster {
    export interface Attr {
      Arn: string;
    }
    export interface CapacityProviderStrategyItem {
      Base?: number;
      CapacityProvider?: string;
      Weight?: number;
    }
    export interface ClusterConfiguration {
      ExecuteCommandConfiguration?: ExecuteCommandConfiguration;
    }
    export interface ClusterSettings {
      Name?: string;
      Value?: string;
    }
    export interface ExecuteCommandConfiguration {
      KmsKeyId?: string;
      LogConfiguration?: ExecuteCommandLogConfiguration;
      Logging?: string;
    }
    export interface ExecuteCommandLogConfiguration {
      CloudWatchEncryptionEnabled?: boolean;
      CloudWatchLogGroupName?: string;
      S3BucketName?: string;
      S3EncryptionEnabled?: boolean;
      S3KeyPrefix?: string;
    }
    export interface ServiceConnectDefaults {
      Namespace?: string;
    }
  }
  export interface ClusterCapacityProviderAssociations {
    CapacityProviders: string[];
    Cluster: string;
    DefaultCapacityProviderStrategy: ClusterCapacityProviderAssociations.CapacityProviderStrategy[];
  }
  export namespace ClusterCapacityProviderAssociations {
    export interface Attr {}
    export interface CapacityProviderStrategy {
      Base?: number;
      CapacityProvider: string;
      Weight?: number;
    }
  }
  export interface PrimaryTaskSet {
    Cluster: string;
    Service: string;
    TaskSetId: string;
  }
  export interface Service {
    CapacityProviderStrategy?: Service.CapacityProviderStrategyItem[];
    Cluster?: string;
    DeploymentConfiguration?: Service.DeploymentConfiguration;
    DeploymentController?: Service.DeploymentController;
    DesiredCount?: number;
    EnableECSManagedTags?: boolean;
    EnableExecuteCommand?: boolean;
    HealthCheckGracePeriodSeconds?: number;
    LaunchType?: string;
    LoadBalancers?: Service.LoadBalancer[];
    NetworkConfiguration?: Service.NetworkConfiguration;
    PlacementConstraints?: Service.PlacementConstraint[];
    PlacementStrategies?: Service.PlacementStrategy[];
    PlatformVersion?: string;
    PropagateTags?: string;
    Role?: string;
    SchedulingStrategy?: string;
    ServiceConnectConfiguration?: Service.ServiceConnectConfiguration;
    ServiceName?: string;
    ServiceRegistries?: Service.ServiceRegistry[];
    Tags?: Tag[];
    TaskDefinition?: string;
  }
  export namespace Service {
    export interface Attr {
      Name: string;
      ServiceArn: string;
    }
    export interface AwsVpcConfiguration {
      AssignPublicIp?: string;
      SecurityGroups?: string[];
      Subnets: string[];
    }
    export interface CapacityProviderStrategyItem {
      Base?: number;
      CapacityProvider?: string;
      Weight?: number;
    }
    export interface DeploymentAlarms {
      AlarmNames: string[];
      Enable: boolean;
      Rollback: boolean;
    }
    export interface DeploymentCircuitBreaker {
      Enable: boolean;
      Rollback: boolean;
    }
    export interface DeploymentConfiguration {
      Alarms?: DeploymentAlarms;
      DeploymentCircuitBreaker?: DeploymentCircuitBreaker;
      MaximumPercent?: number;
      MinimumHealthyPercent?: number;
    }
    export interface DeploymentController {
      Type?: string;
    }
    export interface LoadBalancer {
      ContainerName?: string;
      ContainerPort: number;
      LoadBalancerName?: string;
      TargetGroupArn?: string;
    }
    export interface LogConfiguration {
      LogDriver?: string;
      Options?: Record<string, string>;
      SecretOptions?: Secret[];
    }
    export interface NetworkConfiguration {
      AwsvpcConfiguration?: AwsVpcConfiguration;
    }
    export interface PlacementConstraint {
      Expression?: string;
      Type: string;
    }
    export interface PlacementStrategy {
      Field?: string;
      Type: string;
    }
    export interface Secret {
      Name: string;
      ValueFrom: string;
    }
    export interface ServiceConnectClientAlias {
      DnsName?: string;
      Port: number;
    }
    export interface ServiceConnectConfiguration {
      Enabled: boolean;
      LogConfiguration?: LogConfiguration;
      Namespace?: string;
      Services?: ServiceConnectService[];
    }
    export interface ServiceConnectService {
      ClientAliases?: ServiceConnectClientAlias[];
      DiscoveryName?: string;
      IngressPortOverride?: number;
      PortName: string;
    }
    export interface ServiceRegistry {
      ContainerName?: string;
      ContainerPort?: number;
      Port?: number;
      RegistryArn?: string;
    }
  }
  export interface TaskDefinition {
    ContainerDefinitions?: TaskDefinition.ContainerDefinition[];
    Cpu?: string;
    EphemeralStorage?: TaskDefinition.EphemeralStorage;
    ExecutionRoleArn?: string;
    Family?: string;
    InferenceAccelerators?: TaskDefinition.InferenceAccelerator[];
    IpcMode?: string;
    Memory?: string;
    NetworkMode?: string;
    PidMode?: string;
    PlacementConstraints?: TaskDefinition.TaskDefinitionPlacementConstraint[];
    ProxyConfiguration?: TaskDefinition.ProxyConfiguration;
    RequiresCompatibilities?: string[];
    RuntimePlatform?: TaskDefinition.RuntimePlatform;
    Tags?: Tag[];
    TaskRoleArn?: string;
    Volumes?: TaskDefinition.Volume[];
  }
  export namespace TaskDefinition {
    export interface Attr {
      TaskDefinitionArn: string;
    }
    export interface AuthorizationConfig {
      AccessPointId?: string;
      IAM?: string;
    }
    export interface ContainerDefinition {
      Command?: string[];
      Cpu?: number;
      DependsOn?: ContainerDependency[];
      DisableNetworking?: boolean;
      DnsSearchDomains?: string[];
      DnsServers?: string[];
      DockerLabels?: Record<string, string>;
      DockerSecurityOptions?: string[];
      EntryPoint?: string[];
      Environment?: KeyValuePair[];
      EnvironmentFiles?: EnvironmentFile[];
      Essential?: boolean;
      ExtraHosts?: HostEntry[];
      FirelensConfiguration?: FirelensConfiguration;
      HealthCheck?: HealthCheck;
      Hostname?: string;
      Image: string;
      Interactive?: boolean;
      Links?: string[];
      LinuxParameters?: LinuxParameters;
      LogConfiguration?: LogConfiguration;
      Memory?: number;
      MemoryReservation?: number;
      MountPoints?: MountPoint[];
      Name: string;
      PortMappings?: PortMapping[];
      Privileged?: boolean;
      PseudoTerminal?: boolean;
      ReadonlyRootFilesystem?: boolean;
      RepositoryCredentials?: RepositoryCredentials;
      ResourceRequirements?: ResourceRequirement[];
      Secrets?: Secret[];
      StartTimeout?: number;
      StopTimeout?: number;
      SystemControls?: SystemControl[];
      Ulimits?: Ulimit[];
      User?: string;
      VolumesFrom?: VolumeFrom[];
      WorkingDirectory?: string;
    }
    export interface ContainerDependency {
      Condition?: string;
      ContainerName?: string;
    }
    export interface Device {
      ContainerPath?: string;
      HostPath?: string;
      Permissions?: string[];
    }
    export interface DockerVolumeConfiguration {
      Autoprovision?: boolean;
      Driver?: string;
      DriverOpts?: Record<string, string>;
      Labels?: Record<string, string>;
      Scope?: string;
    }
    export interface EFSVolumeConfiguration {
      AuthorizationConfig?: AuthorizationConfig;
      FilesystemId: string;
      RootDirectory?: string;
      TransitEncryption?: string;
      TransitEncryptionPort?: number;
    }
    export interface EnvironmentFile {
      Type?: string;
      Value?: string;
    }
    export interface EphemeralStorage {
      SizeInGiB?: number;
    }
    export interface FirelensConfiguration {
      Options?: Record<string, string>;
      Type?: string;
    }
    export interface HealthCheck {
      Command?: string[];
      Interval?: number;
      Retries?: number;
      StartPeriod?: number;
      Timeout?: number;
    }
    export interface HostEntry {
      Hostname?: string;
      IpAddress?: string;
    }
    export interface HostVolumeProperties {
      SourcePath?: string;
    }
    export interface InferenceAccelerator {
      DeviceName?: string;
      DeviceType?: string;
    }
    export interface KernelCapabilities {
      Add?: string[];
      Drop?: string[];
    }
    export interface KeyValuePair {
      Name?: string;
      Value?: string;
    }
    export interface LinuxParameters {
      Capabilities?: KernelCapabilities;
      Devices?: Device[];
      InitProcessEnabled?: boolean;
      MaxSwap?: number;
      SharedMemorySize?: number;
      Swappiness?: number;
      Tmpfs?: Tmpfs[];
    }
    export interface LogConfiguration {
      LogDriver: string;
      Options?: Record<string, string>;
      SecretOptions?: Secret[];
    }
    export interface MountPoint {
      ContainerPath?: string;
      ReadOnly?: boolean;
      SourceVolume?: string;
    }
    export interface PortMapping {
      AppProtocol?: string;
      ContainerPort?: number;
      ContainerPortRange?: string;
      HostPort?: number;
      Name?: string;
      Protocol?: string;
    }
    export interface ProxyConfiguration {
      ContainerName: string;
      ProxyConfigurationProperties?: KeyValuePair[];
      Type?: string;
    }
    export interface RepositoryCredentials {
      CredentialsParameter?: string;
    }
    export interface ResourceRequirement {
      Type: string;
      Value: string;
    }
    export interface RuntimePlatform {
      CpuArchitecture?: string;
      OperatingSystemFamily?: string;
    }
    export interface Secret {
      Name: string;
      ValueFrom: string;
    }
    export interface SystemControl {
      Namespace?: string;
      Value?: string;
    }
    export interface TaskDefinitionPlacementConstraint {
      Expression?: string;
      Type: string;
    }
    export interface Tmpfs {
      ContainerPath?: string;
      MountOptions?: string[];
      Size: number;
    }
    export interface Ulimit {
      HardLimit: number;
      Name: string;
      SoftLimit: number;
    }
    export interface Volume {
      DockerVolumeConfiguration?: DockerVolumeConfiguration;
      EFSVolumeConfiguration?: EFSVolumeConfiguration;
      Host?: HostVolumeProperties;
      Name?: string;
    }
    export interface VolumeFrom {
      ReadOnly?: boolean;
      SourceContainer?: string;
    }
  }
  export interface TaskSet {
    Cluster: string;
    ExternalId?: string;
    LaunchType?: string;
    LoadBalancers?: TaskSet.LoadBalancer[];
    NetworkConfiguration?: TaskSet.NetworkConfiguration;
    PlatformVersion?: string;
    Scale?: TaskSet.Scale;
    Service: string;
    ServiceRegistries?: TaskSet.ServiceRegistry[];
    TaskDefinition: string;
  }
  export namespace TaskSet {
    export interface Attr {
      Id: string;
    }
    export interface AwsVpcConfiguration {
      AssignPublicIp?: string;
      SecurityGroups?: string[];
      Subnets: string[];
    }
    export interface LoadBalancer {
      ContainerName?: string;
      ContainerPort?: number;
      LoadBalancerName?: string;
      TargetGroupArn?: string;
    }
    export interface NetworkConfiguration {
      AwsVpcConfiguration?: AwsVpcConfiguration;
    }
    export interface Scale {
      Unit?: string;
      Value?: number;
    }
    export interface ServiceRegistry {
      ContainerName?: string;
      ContainerPort?: number;
      Port?: number;
      RegistryArn?: string;
    }
  }
}
export namespace EFS {
  export interface AccessPoint {
    AccessPointTags?: AccessPoint.AccessPointTag[];
    ClientToken?: string;
    FileSystemId: string;
    PosixUser?: AccessPoint.PosixUser;
    RootDirectory?: AccessPoint.RootDirectory;
  }
  export namespace AccessPoint {
    export interface Attr {
      AccessPointId: string;
      Arn: string;
    }
    export interface AccessPointTag {
      Key?: string;
      Value?: string;
    }
    export interface CreationInfo {
      OwnerGid: string;
      OwnerUid: string;
      Permissions: string;
    }
    export interface PosixUser {
      Gid: string;
      SecondaryGids?: string[];
      Uid: string;
    }
    export interface RootDirectory {
      CreationInfo?: CreationInfo;
      Path?: string;
    }
  }
  export interface FileSystem {
    AvailabilityZoneName?: string;
    BackupPolicy?: FileSystem.BackupPolicy;
    BypassPolicyLockoutSafetyCheck?: boolean;
    Encrypted?: boolean;
    FileSystemPolicy?: any;
    FileSystemTags?: FileSystem.ElasticFileSystemTag[];
    KmsKeyId?: string;
    LifecyclePolicies?: FileSystem.LifecyclePolicy[];
    PerformanceMode?: string;
    ProvisionedThroughputInMibps?: number;
    ThroughputMode?: string;
  }
  export namespace FileSystem {
    export interface Attr {
      Arn: string;
      FileSystemId: string;
    }
    export interface BackupPolicy {
      Status: string;
    }
    export interface ElasticFileSystemTag {
      Key: string;
      Value: string;
    }
    export interface LifecyclePolicy {
      TransitionToIA?: string;
      TransitionToPrimaryStorageClass?: string;
    }
  }
  export interface MountTarget {
    FileSystemId: string;
    IpAddress?: string;
    SecurityGroups: string[];
    SubnetId: string;
  }
}
export namespace EKS {
  export interface Addon {
    AddonName: string;
    AddonVersion?: string;
    ClusterName: string;
    ConfigurationValues?: string;
    PreserveOnDelete?: boolean;
    ResolveConflicts?: string;
    ServiceAccountRoleArn?: string;
    Tags?: Tag[];
  }
  export interface Cluster {
    EncryptionConfig?: Cluster.EncryptionConfig[];
    KubernetesNetworkConfig?: Cluster.KubernetesNetworkConfig;
    Logging?: Cluster.Logging;
    Name?: string;
    OutpostConfig?: Cluster.OutpostConfig;
    ResourcesVpcConfig: Cluster.ResourcesVpcConfig;
    RoleArn: string;
    Tags?: Tag[];
    Version?: string;
  }
  export namespace Cluster {
    export interface Attr {
      Arn: string;
      CertificateAuthorityData: string;
      ClusterSecurityGroupId: string;
      EncryptionConfigKeyArn: string;
      Endpoint: string;
      Id: string;
      "KubernetesNetworkConfig.ServiceIpv6Cidr": string;
      OpenIdConnectIssuerUrl: string;
    }
    export interface ClusterLogging {
      EnabledTypes?: LoggingTypeConfig[];
    }
    export interface ControlPlanePlacement {
      GroupName?: string;
    }
    export interface EncryptionConfig {
      Provider?: Provider;
      Resources?: string[];
    }
    export interface KubernetesNetworkConfig {
      IpFamily?: string;
      ServiceIpv4Cidr?: string;
      ServiceIpv6Cidr?: string;
    }
    export interface Logging {
      ClusterLogging?: ClusterLogging;
    }
    export interface LoggingTypeConfig {
      Type?: string;
    }
    export interface OutpostConfig {
      ControlPlaneInstanceType: string;
      ControlPlanePlacement?: ControlPlanePlacement;
      OutpostArns: string[];
    }
    export interface Provider {
      KeyArn?: string;
    }
    export interface ResourcesVpcConfig {
      EndpointPrivateAccess?: boolean;
      EndpointPublicAccess?: boolean;
      PublicAccessCidrs?: string[];
      SecurityGroupIds?: string[];
      SubnetIds: string[];
    }
  }
  export interface FargateProfile {
    ClusterName: string;
    FargateProfileName?: string;
    PodExecutionRoleArn: string;
    Selectors: FargateProfile.Selector[];
    Subnets?: string[];
    Tags?: Tag[];
  }
  export namespace FargateProfile {
    export interface Attr {
      Arn: string;
    }
    export interface Label {
      Key: string;
      Value: string;
    }
    export interface Selector {
      Labels?: Label[];
      Namespace: string;
    }
  }
  export interface IdentityProviderConfig {
    ClusterName: string;
    IdentityProviderConfigName?: string;
    Oidc?: IdentityProviderConfig.OidcIdentityProviderConfig;
    Tags?: Tag[];
    Type: string;
  }
  export namespace IdentityProviderConfig {
    export interface Attr {
      IdentityProviderConfigArn: string;
    }
    export interface OidcIdentityProviderConfig {
      ClientId: string;
      GroupsClaim?: string;
      GroupsPrefix?: string;
      IssuerUrl: string;
      RequiredClaims?: RequiredClaim[];
      UsernameClaim?: string;
      UsernamePrefix?: string;
    }
    export interface RequiredClaim {
      Key: string;
      Value: string;
    }
  }
  export interface Nodegroup {
    AmiType?: string;
    CapacityType?: string;
    ClusterName: string;
    DiskSize?: number;
    ForceUpdateEnabled?: boolean;
    InstanceTypes?: string[];
    Labels?: Record<string, string>;
    LaunchTemplate?: Nodegroup.LaunchTemplateSpecification;
    NodeRole: string;
    NodegroupName?: string;
    ReleaseVersion?: string;
    RemoteAccess?: Nodegroup.RemoteAccess;
    ScalingConfig?: Nodegroup.ScalingConfig;
    Subnets: string[];
    Tags?: Record<string, string>;
    Taints?: Nodegroup.Taint[];
    UpdateConfig?: Nodegroup.UpdateConfig;
    Version?: string;
  }
  export namespace Nodegroup {
    export interface Attr {
      Arn: string;
      ClusterName: string;
      Id: string;
      NodegroupName: string;
    }
    export interface LaunchTemplateSpecification {
      Id?: string;
      Name?: string;
      Version?: string;
    }
    export interface RemoteAccess {
      Ec2SshKey: string;
      SourceSecurityGroups?: string[];
    }
    export interface ScalingConfig {
      DesiredSize?: number;
      MaxSize?: number;
      MinSize?: number;
    }
    export interface Taint {
      Effect?: string;
      Key?: string;
      Value?: string;
    }
    export interface UpdateConfig {
      MaxUnavailable?: number;
      MaxUnavailablePercentage?: number;
    }
  }
}
export namespace EMR {
  export interface Cluster {
    AdditionalInfo?: any;
    Applications?: Cluster.Application[];
    AutoScalingRole?: string;
    AutoTerminationPolicy?: Cluster.AutoTerminationPolicy;
    BootstrapActions?: Cluster.BootstrapActionConfig[];
    Configurations?: Cluster.Configuration[];
    CustomAmiId?: string;
    EbsRootVolumeSize?: number;
    Instances: Cluster.JobFlowInstancesConfig;
    JobFlowRole: string;
    KerberosAttributes?: Cluster.KerberosAttributes;
    LogEncryptionKmsKeyId?: string;
    LogUri?: string;
    ManagedScalingPolicy?: Cluster.ManagedScalingPolicy;
    Name: string;
    OSReleaseLabel?: string;
    ReleaseLabel?: string;
    ScaleDownBehavior?: string;
    SecurityConfiguration?: string;
    ServiceRole: string;
    StepConcurrencyLevel?: number;
    Steps?: Cluster.StepConfig[];
    Tags?: Tag[];
    VisibleToAllUsers?: boolean;
  }
  export namespace Cluster {
    export interface Attr {
      MasterPublicDNS: string;
    }
    export interface Application {
      AdditionalInfo?: Record<string, string>;
      Args?: string[];
      Name?: string;
      Version?: string;
    }
    export interface AutoScalingPolicy {
      Constraints: ScalingConstraints;
      Rules: ScalingRule[];
    }
    export interface AutoTerminationPolicy {
      IdleTimeout?: number;
    }
    export interface BootstrapActionConfig {
      Name: string;
      ScriptBootstrapAction: ScriptBootstrapActionConfig;
    }
    export interface CloudWatchAlarmDefinition {
      ComparisonOperator: string;
      Dimensions?: MetricDimension[];
      EvaluationPeriods?: number;
      MetricName: string;
      Namespace?: string;
      Period: number;
      Statistic?: string;
      Threshold: number;
      Unit?: string;
    }
    export interface ComputeLimits {
      MaximumCapacityUnits: number;
      MaximumCoreCapacityUnits?: number;
      MaximumOnDemandCapacityUnits?: number;
      MinimumCapacityUnits: number;
      UnitType: string;
    }
    export interface Configuration {
      Classification?: string;
      ConfigurationProperties?: Record<string, string>;
      Configurations?: Configuration[];
    }
    export interface EbsBlockDeviceConfig {
      VolumeSpecification: VolumeSpecification;
      VolumesPerInstance?: number;
    }
    export interface EbsConfiguration {
      EbsBlockDeviceConfigs?: EbsBlockDeviceConfig[];
      EbsOptimized?: boolean;
    }
    export interface HadoopJarStepConfig {
      Args?: string[];
      Jar: string;
      MainClass?: string;
      StepProperties?: KeyValue[];
    }
    export interface InstanceFleetConfig {
      InstanceTypeConfigs?: InstanceTypeConfig[];
      LaunchSpecifications?: InstanceFleetProvisioningSpecifications;
      Name?: string;
      TargetOnDemandCapacity?: number;
      TargetSpotCapacity?: number;
    }
    export interface InstanceFleetProvisioningSpecifications {
      OnDemandSpecification?: OnDemandProvisioningSpecification;
      SpotSpecification?: SpotProvisioningSpecification;
    }
    export interface InstanceGroupConfig {
      AutoScalingPolicy?: AutoScalingPolicy;
      BidPrice?: string;
      Configurations?: Configuration[];
      CustomAmiId?: string;
      EbsConfiguration?: EbsConfiguration;
      InstanceCount: number;
      InstanceType: string;
      Market?: string;
      Name?: string;
    }
    export interface InstanceTypeConfig {
      BidPrice?: string;
      BidPriceAsPercentageOfOnDemandPrice?: number;
      Configurations?: Configuration[];
      CustomAmiId?: string;
      EbsConfiguration?: EbsConfiguration;
      InstanceType: string;
      WeightedCapacity?: number;
    }
    export interface JobFlowInstancesConfig {
      AdditionalMasterSecurityGroups?: string[];
      AdditionalSlaveSecurityGroups?: string[];
      CoreInstanceFleet?: InstanceFleetConfig;
      CoreInstanceGroup?: InstanceGroupConfig;
      Ec2KeyName?: string;
      Ec2SubnetId?: string;
      Ec2SubnetIds?: string[];
      EmrManagedMasterSecurityGroup?: string;
      EmrManagedSlaveSecurityGroup?: string;
      HadoopVersion?: string;
      KeepJobFlowAliveWhenNoSteps?: boolean;
      MasterInstanceFleet?: InstanceFleetConfig;
      MasterInstanceGroup?: InstanceGroupConfig;
      Placement?: PlacementType;
      ServiceAccessSecurityGroup?: string;
      TaskInstanceFleets?: InstanceFleetConfig[];
      TaskInstanceGroups?: InstanceGroupConfig[];
      TerminationProtected?: boolean;
    }
    export interface KerberosAttributes {
      ADDomainJoinPassword?: string;
      ADDomainJoinUser?: string;
      CrossRealmTrustPrincipalPassword?: string;
      KdcAdminPassword: string;
      Realm: string;
    }
    export interface KeyValue {
      Key?: string;
      Value?: string;
    }
    export interface ManagedScalingPolicy {
      ComputeLimits?: ComputeLimits;
    }
    export interface MetricDimension {
      Key: string;
      Value: string;
    }
    export interface OnDemandProvisioningSpecification {
      AllocationStrategy: string;
    }
    export interface PlacementType {
      AvailabilityZone: string;
    }
    export interface ScalingAction {
      Market?: string;
      SimpleScalingPolicyConfiguration: SimpleScalingPolicyConfiguration;
    }
    export interface ScalingConstraints {
      MaxCapacity: number;
      MinCapacity: number;
    }
    export interface ScalingRule {
      Action: ScalingAction;
      Description?: string;
      Name: string;
      Trigger: ScalingTrigger;
    }
    export interface ScalingTrigger {
      CloudWatchAlarmDefinition: CloudWatchAlarmDefinition;
    }
    export interface ScriptBootstrapActionConfig {
      Args?: string[];
      Path: string;
    }
    export interface SimpleScalingPolicyConfiguration {
      AdjustmentType?: string;
      CoolDown?: number;
      ScalingAdjustment: number;
    }
    export interface SpotProvisioningSpecification {
      AllocationStrategy?: string;
      BlockDurationMinutes?: number;
      TimeoutAction: string;
      TimeoutDurationMinutes: number;
    }
    export interface StepConfig {
      ActionOnFailure?: string;
      HadoopJarStep: HadoopJarStepConfig;
      Name: string;
    }
    export interface VolumeSpecification {
      Iops?: number;
      SizeInGB: number;
      VolumeType: string;
    }
  }
  export interface InstanceFleetConfig {
    ClusterId: string;
    InstanceFleetType: string;
    InstanceTypeConfigs?: InstanceFleetConfig.InstanceTypeConfig[];
    LaunchSpecifications?: InstanceFleetConfig.InstanceFleetProvisioningSpecifications;
    Name?: string;
    TargetOnDemandCapacity?: number;
    TargetSpotCapacity?: number;
  }
  export namespace InstanceFleetConfig {
    export interface Attr {}
    export interface Configuration {
      Classification?: string;
      ConfigurationProperties?: Record<string, string>;
      Configurations?: Configuration[];
    }
    export interface EbsBlockDeviceConfig {
      VolumeSpecification: VolumeSpecification;
      VolumesPerInstance?: number;
    }
    export interface EbsConfiguration {
      EbsBlockDeviceConfigs?: EbsBlockDeviceConfig[];
      EbsOptimized?: boolean;
    }
    export interface InstanceFleetProvisioningSpecifications {
      OnDemandSpecification?: OnDemandProvisioningSpecification;
      SpotSpecification?: SpotProvisioningSpecification;
    }
    export interface InstanceTypeConfig {
      BidPrice?: string;
      BidPriceAsPercentageOfOnDemandPrice?: number;
      Configurations?: Configuration[];
      CustomAmiId?: string;
      EbsConfiguration?: EbsConfiguration;
      InstanceType: string;
      WeightedCapacity?: number;
    }
    export interface OnDemandProvisioningSpecification {
      AllocationStrategy: string;
    }
    export interface SpotProvisioningSpecification {
      AllocationStrategy?: string;
      BlockDurationMinutes?: number;
      TimeoutAction: string;
      TimeoutDurationMinutes: number;
    }
    export interface VolumeSpecification {
      Iops?: number;
      SizeInGB: number;
      VolumeType: string;
    }
  }
  export interface InstanceGroupConfig {
    AutoScalingPolicy?: InstanceGroupConfig.AutoScalingPolicy;
    BidPrice?: string;
    Configurations?: InstanceGroupConfig.Configuration[];
    CustomAmiId?: string;
    EbsConfiguration?: InstanceGroupConfig.EbsConfiguration;
    InstanceCount: number;
    InstanceRole: string;
    InstanceType: string;
    JobFlowId: string;
    Market?: string;
    Name?: string;
  }
  export namespace InstanceGroupConfig {
    export interface Attr {}
    export interface AutoScalingPolicy {
      Constraints: ScalingConstraints;
      Rules: ScalingRule[];
    }
    export interface CloudWatchAlarmDefinition {
      ComparisonOperator: string;
      Dimensions?: MetricDimension[];
      EvaluationPeriods?: number;
      MetricName: string;
      Namespace?: string;
      Period: number;
      Statistic?: string;
      Threshold: number;
      Unit?: string;
    }
    export interface Configuration {
      Classification?: string;
      ConfigurationProperties?: Record<string, string>;
      Configurations?: Configuration[];
    }
    export interface EbsBlockDeviceConfig {
      VolumeSpecification: VolumeSpecification;
      VolumesPerInstance?: number;
    }
    export interface EbsConfiguration {
      EbsBlockDeviceConfigs?: EbsBlockDeviceConfig[];
      EbsOptimized?: boolean;
    }
    export interface MetricDimension {
      Key: string;
      Value: string;
    }
    export interface ScalingAction {
      Market?: string;
      SimpleScalingPolicyConfiguration: SimpleScalingPolicyConfiguration;
    }
    export interface ScalingConstraints {
      MaxCapacity: number;
      MinCapacity: number;
    }
    export interface ScalingRule {
      Action: ScalingAction;
      Description?: string;
      Name: string;
      Trigger: ScalingTrigger;
    }
    export interface ScalingTrigger {
      CloudWatchAlarmDefinition: CloudWatchAlarmDefinition;
    }
    export interface SimpleScalingPolicyConfiguration {
      AdjustmentType?: string;
      CoolDown?: number;
      ScalingAdjustment: number;
    }
    export interface VolumeSpecification {
      Iops?: number;
      SizeInGB: number;
      VolumeType: string;
    }
  }
  export interface SecurityConfiguration {
    Name?: string;
    SecurityConfiguration: any;
  }
  export interface Step {
    ActionOnFailure: string;
    HadoopJarStep: Step.HadoopJarStepConfig;
    JobFlowId: string;
    Name: string;
  }
  export namespace Step {
    export interface Attr {}
    export interface HadoopJarStepConfig {
      Args?: string[];
      Jar: string;
      MainClass?: string;
      StepProperties?: KeyValue[];
    }
    export interface KeyValue {
      Key?: string;
      Value?: string;
    }
  }
  export interface Studio {
    AuthMode: string;
    DefaultS3Location: string;
    Description?: string;
    EngineSecurityGroupId: string;
    IdpAuthUrl?: string;
    IdpRelayStateParameterName?: string;
    Name: string;
    ServiceRole: string;
    SubnetIds: string[];
    Tags?: Tag[];
    UserRole?: string;
    VpcId: string;
    WorkspaceSecurityGroupId: string;
  }
  export interface StudioSessionMapping {
    IdentityName: string;
    IdentityType: string;
    SessionPolicyArn: string;
    StudioId: string;
  }
}
export namespace EMRContainers {
  export interface VirtualCluster {
    ContainerProvider: VirtualCluster.ContainerProvider;
    Name: string;
    Tags?: Tag[];
  }
  export namespace VirtualCluster {
    export interface Attr {
      Arn: string;
      Id: string;
    }
    export interface ContainerInfo {
      EksInfo: EksInfo;
    }
    export interface ContainerProvider {
      Id: string;
      Info: ContainerInfo;
      Type: string;
    }
    export interface EksInfo {
      Namespace: string;
    }
  }
}
export namespace EMRServerless {
  export interface Application {
    Architecture?: string;
    AutoStartConfiguration?: Application.AutoStartConfiguration;
    AutoStopConfiguration?: Application.AutoStopConfiguration;
    InitialCapacity?: Application.InitialCapacityConfigKeyValuePair[];
    MaximumCapacity?: Application.MaximumAllowedResources;
    Name?: string;
    NetworkConfiguration?: Application.NetworkConfiguration;
    ReleaseLabel: string;
    Tags?: Tag[];
    Type: string;
  }
  export namespace Application {
    export interface Attr {
      ApplicationId: string;
      Arn: string;
    }
    export interface AutoStartConfiguration {
      Enabled?: boolean;
    }
    export interface AutoStopConfiguration {
      Enabled?: boolean;
      IdleTimeoutMinutes?: number;
    }
    export interface InitialCapacityConfig {
      WorkerConfiguration: WorkerConfiguration;
      WorkerCount: number;
    }
    export interface InitialCapacityConfigKeyValuePair {
      Key: string;
      Value: InitialCapacityConfig;
    }
    export interface MaximumAllowedResources {
      Cpu: string;
      Disk?: string;
      Memory: string;
    }
    export interface NetworkConfiguration {
      SecurityGroupIds?: string[];
      SubnetIds?: string[];
    }
    export interface WorkerConfiguration {
      Cpu: string;
      Disk?: string;
      Memory: string;
    }
  }
}
export namespace ElastiCache {
  export interface CacheCluster {
    AZMode?: string;
    AutoMinorVersionUpgrade?: boolean;
    CacheNodeType: string;
    CacheParameterGroupName?: string;
    CacheSecurityGroupNames?: string[];
    CacheSubnetGroupName?: string;
    ClusterName?: string;
    Engine: string;
    EngineVersion?: string;
    IpDiscovery?: string;
    LogDeliveryConfigurations?: CacheCluster.LogDeliveryConfigurationRequest[];
    NetworkType?: string;
    NotificationTopicArn?: string;
    NumCacheNodes: number;
    Port?: number;
    PreferredAvailabilityZone?: string;
    PreferredAvailabilityZones?: string[];
    PreferredMaintenanceWindow?: string;
    SnapshotArns?: string[];
    SnapshotName?: string;
    SnapshotRetentionLimit?: number;
    SnapshotWindow?: string;
    Tags?: Tag[];
    TransitEncryptionEnabled?: boolean;
    VpcSecurityGroupIds?: string[];
  }
  export namespace CacheCluster {
    export interface Attr {
      "ConfigurationEndpoint.Address": string;
      "ConfigurationEndpoint.Port": string;
      "RedisEndpoint.Address": string;
      "RedisEndpoint.Port": string;
    }
    export interface CloudWatchLogsDestinationDetails {
      LogGroup: string;
    }
    export interface DestinationDetails {
      CloudWatchLogsDetails?: CloudWatchLogsDestinationDetails;
      KinesisFirehoseDetails?: KinesisFirehoseDestinationDetails;
    }
    export interface KinesisFirehoseDestinationDetails {
      DeliveryStream: string;
    }
    export interface LogDeliveryConfigurationRequest {
      DestinationDetails: DestinationDetails;
      DestinationType: string;
      LogFormat: string;
      LogType: string;
    }
  }
  export interface GlobalReplicationGroup {
    AutomaticFailoverEnabled?: boolean;
    CacheNodeType?: string;
    CacheParameterGroupName?: string;
    EngineVersion?: string;
    GlobalNodeGroupCount?: number;
    GlobalReplicationGroupDescription?: string;
    GlobalReplicationGroupIdSuffix?: string;
    Members: GlobalReplicationGroup.GlobalReplicationGroupMember[];
    RegionalConfigurations?: GlobalReplicationGroup.RegionalConfiguration[];
  }
  export namespace GlobalReplicationGroup {
    export interface Attr {
      GlobalReplicationGroupId: string;
      Status: string;
    }
    export interface GlobalReplicationGroupMember {
      ReplicationGroupId?: string;
      ReplicationGroupRegion?: string;
      Role?: string;
    }
    export interface RegionalConfiguration {
      ReplicationGroupId?: string;
      ReplicationGroupRegion?: string;
      ReshardingConfigurations?: ReshardingConfiguration[];
    }
    export interface ReshardingConfiguration {
      NodeGroupId?: string;
      PreferredAvailabilityZones?: string[];
    }
  }
  export interface ParameterGroup {
    CacheParameterGroupFamily: string;
    Description: string;
    Properties?: Record<string, string>;
    Tags?: Tag[];
  }
  export interface ReplicationGroup {
    AtRestEncryptionEnabled?: boolean;
    AuthToken?: string;
    AutoMinorVersionUpgrade?: boolean;
    AutomaticFailoverEnabled?: boolean;
    CacheNodeType?: string;
    CacheParameterGroupName?: string;
    CacheSecurityGroupNames?: string[];
    CacheSubnetGroupName?: string;
    DataTieringEnabled?: boolean;
    Engine?: string;
    EngineVersion?: string;
    GlobalReplicationGroupId?: string;
    IpDiscovery?: string;
    KmsKeyId?: string;
    LogDeliveryConfigurations?: ReplicationGroup.LogDeliveryConfigurationRequest[];
    MultiAZEnabled?: boolean;
    NetworkType?: string;
    NodeGroupConfiguration?: ReplicationGroup.NodeGroupConfiguration[];
    NotificationTopicArn?: string;
    NumCacheClusters?: number;
    NumNodeGroups?: number;
    Port?: number;
    PreferredCacheClusterAZs?: string[];
    PreferredMaintenanceWindow?: string;
    PrimaryClusterId?: string;
    ReplicasPerNodeGroup?: number;
    ReplicationGroupDescription: string;
    ReplicationGroupId?: string;
    SecurityGroupIds?: string[];
    SnapshotArns?: string[];
    SnapshotName?: string;
    SnapshotRetentionLimit?: number;
    SnapshotWindow?: string;
    SnapshottingClusterId?: string;
    Tags?: Tag[];
    TransitEncryptionEnabled?: boolean;
    UserGroupIds?: string[];
  }
  export namespace ReplicationGroup {
    export interface Attr {
      "ConfigurationEndPoint.Address": string;
      "ConfigurationEndPoint.Port": string;
      "PrimaryEndPoint.Address": string;
      "PrimaryEndPoint.Port": string;
      "ReadEndPoint.Addresses": string;
      "ReadEndPoint.Addresses.List": string[];
      "ReadEndPoint.Ports": string;
      "ReadEndPoint.Ports.List": string[];
      "ReaderEndPoint.Address": string;
      "ReaderEndPoint.Port": string;
    }
    export interface CloudWatchLogsDestinationDetails {
      LogGroup: string;
    }
    export interface DestinationDetails {
      CloudWatchLogsDetails?: CloudWatchLogsDestinationDetails;
      KinesisFirehoseDetails?: KinesisFirehoseDestinationDetails;
    }
    export interface KinesisFirehoseDestinationDetails {
      DeliveryStream: string;
    }
    export interface LogDeliveryConfigurationRequest {
      DestinationDetails: DestinationDetails;
      DestinationType: string;
      LogFormat: string;
      LogType: string;
    }
    export interface NodeGroupConfiguration {
      NodeGroupId?: string;
      PrimaryAvailabilityZone?: string;
      ReplicaAvailabilityZones?: string[];
      ReplicaCount?: number;
      Slots?: string;
    }
  }
  export interface SecurityGroup {
    Description: string;
    Tags?: Tag[];
  }
  export interface SecurityGroupIngress {
    CacheSecurityGroupName: string;
    EC2SecurityGroupName: string;
    EC2SecurityGroupOwnerId?: string;
  }
  export interface SubnetGroup {
    CacheSubnetGroupName?: string;
    Description: string;
    SubnetIds: string[];
    Tags?: Tag[];
  }
  export interface User {
    AccessString?: string;
    AuthenticationMode?: any;
    Engine: string;
    NoPasswordRequired?: boolean;
    Passwords?: string[];
    UserId: string;
    UserName: string;
  }
  export namespace User {
    export interface Attr {
      Arn: string;
      Status: string;
    }
    export interface AuthenticationMode {
      Passwords?: string[];
      Type: string;
    }
  }
  export interface UserGroup {
    Engine: string;
    UserGroupId: string;
    UserIds?: string[];
  }
}
export namespace ElasticBeanstalk {
  export interface Application {
    ApplicationName?: string;
    Description?: string;
    ResourceLifecycleConfig?: Application.ApplicationResourceLifecycleConfig;
  }
  export namespace Application {
    export interface Attr {}
    export interface ApplicationResourceLifecycleConfig {
      ServiceRole?: string;
      VersionLifecycleConfig?: ApplicationVersionLifecycleConfig;
    }
    export interface ApplicationVersionLifecycleConfig {
      MaxAgeRule?: MaxAgeRule;
      MaxCountRule?: MaxCountRule;
    }
    export interface MaxAgeRule {
      DeleteSourceFromS3?: boolean;
      Enabled?: boolean;
      MaxAgeInDays?: number;
    }
    export interface MaxCountRule {
      DeleteSourceFromS3?: boolean;
      Enabled?: boolean;
      MaxCount?: number;
    }
  }
  export interface ApplicationVersion {
    ApplicationName: string;
    Description?: string;
    SourceBundle: ApplicationVersion.SourceBundle;
  }
  export namespace ApplicationVersion {
    export interface Attr {
      Id: string;
    }
    export interface SourceBundle {
      S3Bucket: string;
      S3Key: string;
    }
  }
  export interface ConfigurationTemplate {
    ApplicationName: string;
    Description?: string;
    EnvironmentId?: string;
    OptionSettings?: ConfigurationTemplate.ConfigurationOptionSetting[];
    PlatformArn?: string;
    SolutionStackName?: string;
    SourceConfiguration?: ConfigurationTemplate.SourceConfiguration;
  }
  export namespace ConfigurationTemplate {
    export interface Attr {
      TemplateName: string;
    }
    export interface ConfigurationOptionSetting {
      Namespace: string;
      OptionName: string;
      ResourceName?: string;
      Value?: string;
    }
    export interface SourceConfiguration {
      ApplicationName: string;
      TemplateName: string;
    }
  }
  export interface Environment {
    ApplicationName: string;
    CNAMEPrefix?: string;
    Description?: string;
    EnvironmentName?: string;
    OperationsRole?: string;
    OptionSettings?: Environment.OptionSetting[];
    PlatformArn?: string;
    SolutionStackName?: string;
    Tags?: Tag[];
    TemplateName?: string;
    Tier?: Environment.Tier;
    VersionLabel?: string;
  }
  export namespace Environment {
    export interface Attr {
      EndpointURL: string;
    }
    export interface OptionSetting {
      Namespace: string;
      OptionName: string;
      ResourceName?: string;
      Value?: string;
    }
    export interface Tier {
      Name?: string;
      Type?: string;
      Version?: string;
    }
  }
}
export namespace ElasticLoadBalancing {
  export interface LoadBalancer {
    AccessLoggingPolicy?: LoadBalancer.AccessLoggingPolicy;
    AppCookieStickinessPolicy?: LoadBalancer.AppCookieStickinessPolicy[];
    AvailabilityZones?: string[];
    ConnectionDrainingPolicy?: LoadBalancer.ConnectionDrainingPolicy;
    ConnectionSettings?: LoadBalancer.ConnectionSettings;
    CrossZone?: boolean;
    HealthCheck?: LoadBalancer.HealthCheck;
    Instances?: string[];
    LBCookieStickinessPolicy?: LoadBalancer.LBCookieStickinessPolicy[];
    Listeners: LoadBalancer.Listeners[];
    LoadBalancerName?: string;
    Policies?: LoadBalancer.Policies[];
    Scheme?: string;
    SecurityGroups?: string[];
    Subnets?: string[];
    Tags?: Tag[];
  }
  export namespace LoadBalancer {
    export interface Attr {
      CanonicalHostedZoneName: string;
      CanonicalHostedZoneNameID: string;
      DNSName: string;
      "SourceSecurityGroup.GroupName": string;
      "SourceSecurityGroup.OwnerAlias": string;
    }
    export interface AccessLoggingPolicy {
      EmitInterval?: number;
      Enabled: boolean;
      S3BucketName: string;
      S3BucketPrefix?: string;
    }
    export interface AppCookieStickinessPolicy {
      CookieName: string;
      PolicyName: string;
    }
    export interface ConnectionDrainingPolicy {
      Enabled: boolean;
      Timeout?: number;
    }
    export interface ConnectionSettings {
      IdleTimeout: number;
    }
    export interface HealthCheck {
      HealthyThreshold: string;
      Interval: string;
      Target: string;
      Timeout: string;
      UnhealthyThreshold: string;
    }
    export interface LBCookieStickinessPolicy {
      CookieExpirationPeriod?: string;
      PolicyName?: string;
    }
    export interface Listeners {
      InstancePort: string;
      InstanceProtocol?: string;
      LoadBalancerPort: string;
      PolicyNames?: string[];
      Protocol: string;
      SSLCertificateId?: string;
    }
    export interface Policies {
      Attributes: any[];
      InstancePorts?: string[];
      LoadBalancerPorts?: string[];
      PolicyName: string;
      PolicyType: string;
    }
  }
}
export namespace ElasticLoadBalancingV2 {
  export interface Listener {
    AlpnPolicy?: string[];
    Certificates?: Listener.Certificate[];
    DefaultActions: Listener.Action[];
    LoadBalancerArn: string;
    Port?: number;
    Protocol?: string;
    SslPolicy?: string;
  }
  export namespace Listener {
    export interface Attr {
      ListenerArn: string;
    }
    export interface Action {
      AuthenticateCognitoConfig?: AuthenticateCognitoConfig;
      AuthenticateOidcConfig?: AuthenticateOidcConfig;
      FixedResponseConfig?: FixedResponseConfig;
      ForwardConfig?: ForwardConfig;
      Order?: number;
      RedirectConfig?: RedirectConfig;
      TargetGroupArn?: string;
      Type: string;
    }
    export interface AuthenticateCognitoConfig {
      AuthenticationRequestExtraParams?: Record<string, string>;
      OnUnauthenticatedRequest?: string;
      Scope?: string;
      SessionCookieName?: string;
      SessionTimeout?: string;
      UserPoolArn: string;
      UserPoolClientId: string;
      UserPoolDomain: string;
    }
    export interface AuthenticateOidcConfig {
      AuthenticationRequestExtraParams?: Record<string, string>;
      AuthorizationEndpoint: string;
      ClientId: string;
      ClientSecret?: string;
      Issuer: string;
      OnUnauthenticatedRequest?: string;
      Scope?: string;
      SessionCookieName?: string;
      SessionTimeout?: string;
      TokenEndpoint: string;
      UseExistingClientSecret?: boolean;
      UserInfoEndpoint: string;
    }
    export interface Certificate {
      CertificateArn?: string;
    }
    export interface FixedResponseConfig {
      ContentType?: string;
      MessageBody?: string;
      StatusCode: string;
    }
    export interface ForwardConfig {
      TargetGroupStickinessConfig?: TargetGroupStickinessConfig;
      TargetGroups?: TargetGroupTuple[];
    }
    export interface RedirectConfig {
      Host?: string;
      Path?: string;
      Port?: string;
      Protocol?: string;
      Query?: string;
      StatusCode: string;
    }
    export interface TargetGroupStickinessConfig {
      DurationSeconds?: number;
      Enabled?: boolean;
    }
    export interface TargetGroupTuple {
      TargetGroupArn?: string;
      Weight?: number;
    }
  }
  export interface ListenerCertificate {
    Certificates: ListenerCertificate.Certificate[];
    ListenerArn: string;
  }
  export namespace ListenerCertificate {
    export interface Attr {}
    export interface Certificate {
      CertificateArn?: string;
    }
  }
  export interface ListenerRule {
    Actions: ListenerRule.Action[];
    Conditions: ListenerRule.RuleCondition[];
    ListenerArn: string;
    Priority: number;
  }
  export namespace ListenerRule {
    export interface Attr {
      IsDefault: boolean;
      RuleArn: string;
    }
    export interface Action {
      AuthenticateCognitoConfig?: AuthenticateCognitoConfig;
      AuthenticateOidcConfig?: AuthenticateOidcConfig;
      FixedResponseConfig?: FixedResponseConfig;
      ForwardConfig?: ForwardConfig;
      Order?: number;
      RedirectConfig?: RedirectConfig;
      TargetGroupArn?: string;
      Type: string;
    }
    export interface AuthenticateCognitoConfig {
      AuthenticationRequestExtraParams?: Record<string, string>;
      OnUnauthenticatedRequest?: string;
      Scope?: string;
      SessionCookieName?: string;
      SessionTimeout?: number;
      UserPoolArn: string;
      UserPoolClientId: string;
      UserPoolDomain: string;
    }
    export interface AuthenticateOidcConfig {
      AuthenticationRequestExtraParams?: Record<string, string>;
      AuthorizationEndpoint: string;
      ClientId: string;
      ClientSecret?: string;
      Issuer: string;
      OnUnauthenticatedRequest?: string;
      Scope?: string;
      SessionCookieName?: string;
      SessionTimeout?: number;
      TokenEndpoint: string;
      UseExistingClientSecret?: boolean;
      UserInfoEndpoint: string;
    }
    export interface FixedResponseConfig {
      ContentType?: string;
      MessageBody?: string;
      StatusCode: string;
    }
    export interface ForwardConfig {
      TargetGroupStickinessConfig?: TargetGroupStickinessConfig;
      TargetGroups?: TargetGroupTuple[];
    }
    export interface HostHeaderConfig {
      Values?: string[];
    }
    export interface HttpHeaderConfig {
      HttpHeaderName?: string;
      Values?: string[];
    }
    export interface HttpRequestMethodConfig {
      Values?: string[];
    }
    export interface PathPatternConfig {
      Values?: string[];
    }
    export interface QueryStringConfig {
      Values?: QueryStringKeyValue[];
    }
    export interface QueryStringKeyValue {
      Key?: string;
      Value?: string;
    }
    export interface RedirectConfig {
      Host?: string;
      Path?: string;
      Port?: string;
      Protocol?: string;
      Query?: string;
      StatusCode: string;
    }
    export interface RuleCondition {
      Field?: string;
      HostHeaderConfig?: HostHeaderConfig;
      HttpHeaderConfig?: HttpHeaderConfig;
      HttpRequestMethodConfig?: HttpRequestMethodConfig;
      PathPatternConfig?: PathPatternConfig;
      QueryStringConfig?: QueryStringConfig;
      SourceIpConfig?: SourceIpConfig;
      Values?: string[];
    }
    export interface SourceIpConfig {
      Values?: string[];
    }
    export interface TargetGroupStickinessConfig {
      DurationSeconds?: number;
      Enabled?: boolean;
    }
    export interface TargetGroupTuple {
      TargetGroupArn?: string;
      Weight?: number;
    }
  }
  export interface LoadBalancer {
    IpAddressType?: string;
    LoadBalancerAttributes?: LoadBalancer.LoadBalancerAttribute[];
    Name?: string;
    Scheme?: string;
    SecurityGroups?: string[];
    SubnetMappings?: LoadBalancer.SubnetMapping[];
    Subnets?: string[];
    Tags?: Tag[];
    Type?: string;
  }
  export namespace LoadBalancer {
    export interface Attr {
      CanonicalHostedZoneID: string;
      DNSName: string;
      LoadBalancerFullName: string;
      LoadBalancerName: string;
      SecurityGroups: string[];
    }
    export interface LoadBalancerAttribute {
      Key?: string;
      Value?: string;
    }
    export interface SubnetMapping {
      AllocationId?: string;
      IPv6Address?: string;
      PrivateIPv4Address?: string;
      SubnetId: string;
    }
  }
  export interface TargetGroup {
    HealthCheckEnabled?: boolean;
    HealthCheckIntervalSeconds?: number;
    HealthCheckPath?: string;
    HealthCheckPort?: string;
    HealthCheckProtocol?: string;
    HealthCheckTimeoutSeconds?: number;
    HealthyThresholdCount?: number;
    IpAddressType?: string;
    Matcher?: TargetGroup.Matcher;
    Name?: string;
    Port?: number;
    Protocol?: string;
    ProtocolVersion?: string;
    Tags?: Tag[];
    TargetGroupAttributes?: TargetGroup.TargetGroupAttribute[];
    TargetType?: string;
    Targets?: TargetGroup.TargetDescription[];
    UnhealthyThresholdCount?: number;
    VpcId?: string;
  }
  export namespace TargetGroup {
    export interface Attr {
      LoadBalancerArns: string[];
      TargetGroupArn: string;
      TargetGroupFullName: string;
      TargetGroupName: string;
    }
    export interface Matcher {
      GrpcCode?: string;
      HttpCode?: string;
    }
    export interface TargetDescription {
      AvailabilityZone?: string;
      Id: string;
      Port?: number;
    }
    export interface TargetGroupAttribute {
      Key?: string;
      Value?: string;
    }
  }
}
export namespace Elasticsearch {
  export interface Domain {
    AccessPolicies?: any;
    AdvancedOptions?: Record<string, string>;
    AdvancedSecurityOptions?: Domain.AdvancedSecurityOptionsInput;
    CognitoOptions?: Domain.CognitoOptions;
    DomainEndpointOptions?: Domain.DomainEndpointOptions;
    DomainName?: string;
    EBSOptions?: Domain.EBSOptions;
    ElasticsearchClusterConfig?: Domain.ElasticsearchClusterConfig;
    ElasticsearchVersion?: string;
    EncryptionAtRestOptions?: Domain.EncryptionAtRestOptions;
    LogPublishingOptions?: Record<string, Domain.LogPublishingOption>;
    NodeToNodeEncryptionOptions?: Domain.NodeToNodeEncryptionOptions;
    SnapshotOptions?: Domain.SnapshotOptions;
    Tags?: Tag[];
    VPCOptions?: Domain.VPCOptions;
  }
  export namespace Domain {
    export interface Attr {
      Arn: string;
      DomainEndpoint: string;
    }
    export interface AdvancedSecurityOptionsInput {
      AnonymousAuthEnabled?: boolean;
      Enabled?: boolean;
      InternalUserDatabaseEnabled?: boolean;
      MasterUserOptions?: MasterUserOptions;
    }
    export interface CognitoOptions {
      Enabled?: boolean;
      IdentityPoolId?: string;
      RoleArn?: string;
      UserPoolId?: string;
    }
    export interface ColdStorageOptions {
      Enabled?: boolean;
    }
    export interface DomainEndpointOptions {
      CustomEndpoint?: string;
      CustomEndpointCertificateArn?: string;
      CustomEndpointEnabled?: boolean;
      EnforceHTTPS?: boolean;
      TLSSecurityPolicy?: string;
    }
    export interface EBSOptions {
      EBSEnabled?: boolean;
      Iops?: number;
      VolumeSize?: number;
      VolumeType?: string;
    }
    export interface ElasticsearchClusterConfig {
      ColdStorageOptions?: ColdStorageOptions;
      DedicatedMasterCount?: number;
      DedicatedMasterEnabled?: boolean;
      DedicatedMasterType?: string;
      InstanceCount?: number;
      InstanceType?: string;
      WarmCount?: number;
      WarmEnabled?: boolean;
      WarmType?: string;
      ZoneAwarenessConfig?: ZoneAwarenessConfig;
      ZoneAwarenessEnabled?: boolean;
    }
    export interface EncryptionAtRestOptions {
      Enabled?: boolean;
      KmsKeyId?: string;
    }
    export interface LogPublishingOption {
      CloudWatchLogsLogGroupArn?: string;
      Enabled?: boolean;
    }
    export interface MasterUserOptions {
      MasterUserARN?: string;
      MasterUserName?: string;
      MasterUserPassword?: string;
    }
    export interface NodeToNodeEncryptionOptions {
      Enabled?: boolean;
    }
    export interface SnapshotOptions {
      AutomatedSnapshotStartHour?: number;
    }
    export interface VPCOptions {
      SecurityGroupIds?: string[];
      SubnetIds?: string[];
    }
    export interface ZoneAwarenessConfig {
      AvailabilityZoneCount?: number;
    }
  }
}
export namespace EventSchemas {
  export interface Discoverer {
    CrossAccount?: boolean;
    Description?: string;
    SourceArn: string;
    Tags?: Discoverer.TagsEntry[];
  }
  export namespace Discoverer {
    export interface Attr {
      CrossAccount: boolean;
      DiscovererArn: string;
      DiscovererId: string;
    }
    export interface TagsEntry {
      Key: string;
      Value: string;
    }
  }
  export interface Registry {
    Description?: string;
    RegistryName?: string;
    Tags?: Registry.TagsEntry[];
  }
  export namespace Registry {
    export interface Attr {
      RegistryArn: string;
      RegistryName: string;
    }
    export interface TagsEntry {
      Key: string;
      Value: string;
    }
  }
  export interface RegistryPolicy {
    Policy: any;
    RegistryName: string;
    RevisionId?: string;
  }
  export interface Schema {
    Content: string;
    Description?: string;
    RegistryName: string;
    SchemaName?: string;
    Tags?: Schema.TagsEntry[];
    Type: string;
  }
  export namespace Schema {
    export interface Attr {
      SchemaArn: string;
      SchemaName: string;
      SchemaVersion: string;
    }
    export interface TagsEntry {
      Key: string;
      Value: string;
    }
  }
}
export namespace Events {
  export interface ApiDestination {
    ConnectionArn: string;
    Description?: string;
    HttpMethod: string;
    InvocationEndpoint: string;
    InvocationRateLimitPerSecond?: number;
    Name?: string;
  }
  export interface Archive {
    ArchiveName?: string;
    Description?: string;
    EventPattern?: any;
    RetentionDays?: number;
    SourceArn: string;
  }
  export interface Connection {
    AuthParameters: Connection.AuthParameters;
    AuthorizationType: string;
    Description?: string;
    Name?: string;
  }
  export namespace Connection {
    export interface Attr {
      Arn: string;
      SecretArn: string;
    }
    export interface ApiKeyAuthParameters {
      ApiKeyName: string;
      ApiKeyValue: string;
    }
    export interface AuthParameters {
      ApiKeyAuthParameters?: ApiKeyAuthParameters;
      BasicAuthParameters?: BasicAuthParameters;
      InvocationHttpParameters?: ConnectionHttpParameters;
      OAuthParameters?: OAuthParameters;
    }
    export interface BasicAuthParameters {
      Password: string;
      Username: string;
    }
    export interface ClientParameters {
      ClientID: string;
      ClientSecret: string;
    }
    export interface ConnectionHttpParameters {
      BodyParameters?: Parameter[];
      HeaderParameters?: Parameter[];
      QueryStringParameters?: Parameter[];
    }
    export interface OAuthParameters {
      AuthorizationEndpoint: string;
      ClientParameters: ClientParameters;
      HttpMethod: string;
      OAuthHttpParameters?: ConnectionHttpParameters;
    }
    export interface Parameter {
      IsValueSecret?: boolean;
      Key: string;
      Value: string;
    }
  }
  export interface Endpoint {
    Description?: string;
    EventBuses: Endpoint.EndpointEventBus[];
    Name: string;
    ReplicationConfig?: Endpoint.ReplicationConfig;
    RoleArn?: string;
    RoutingConfig: Endpoint.RoutingConfig;
  }
  export namespace Endpoint {
    export interface Attr {
      Arn: string;
      EndpointId: string;
      EndpointUrl: string;
      State: string;
      StateReason: string;
    }
    export interface EndpointEventBus {
      EventBusArn: string;
    }
    export interface FailoverConfig {
      Primary: Primary;
      Secondary: Secondary;
    }
    export interface Primary {
      HealthCheck: string;
    }
    export interface ReplicationConfig {
      State: string;
    }
    export interface RoutingConfig {
      FailoverConfig: FailoverConfig;
    }
    export interface Secondary {
      Route: string;
    }
  }
  export interface EventBus {
    EventSourceName?: string;
    Name: string;
    Tags?: EventBus.TagEntry[];
  }
  export namespace EventBus {
    export interface Attr {
      Arn: string;
      Name: string;
      Policy: string;
    }
    export interface TagEntry {
      Key: string;
      Value: string;
    }
  }
  export interface EventBusPolicy {
    Action?: string;
    Condition?: EventBusPolicy.Condition;
    EventBusName?: string;
    Principal?: string;
    Statement?: any;
    StatementId: string;
  }
  export namespace EventBusPolicy {
    export interface Attr {}
    export interface Condition {
      Key?: string;
      Type?: string;
      Value?: string;
    }
  }
  export interface Rule {
    Description?: string;
    EventBusName?: string;
    EventPattern?: any;
    Name?: string;
    RoleArn?: string;
    ScheduleExpression?: string;
    State?: string;
    Targets?: Rule.Target[];
  }
  export namespace Rule {
    export interface Attr {
      Arn: string;
    }
    export interface AwsVpcConfiguration {
      AssignPublicIp?: string;
      SecurityGroups?: string[];
      Subnets: string[];
    }
    export interface BatchArrayProperties {
      Size?: number;
    }
    export interface BatchParameters {
      ArrayProperties?: BatchArrayProperties;
      JobDefinition: string;
      JobName: string;
      RetryStrategy?: BatchRetryStrategy;
    }
    export interface BatchRetryStrategy {
      Attempts?: number;
    }
    export interface CapacityProviderStrategyItem {
      Base?: number;
      CapacityProvider: string;
      Weight?: number;
    }
    export interface DeadLetterConfig {
      Arn?: string;
    }
    export interface EcsParameters {
      CapacityProviderStrategy?: CapacityProviderStrategyItem[];
      EnableECSManagedTags?: boolean;
      EnableExecuteCommand?: boolean;
      Group?: string;
      LaunchType?: string;
      NetworkConfiguration?: NetworkConfiguration;
      PlacementConstraints?: PlacementConstraint[];
      PlacementStrategies?: PlacementStrategy[];
      PlatformVersion?: string;
      PropagateTags?: string;
      ReferenceId?: string;
      TagList?: Tag[];
      TaskCount?: number;
      TaskDefinitionArn: string;
    }
    export interface HttpParameters {
      HeaderParameters?: Record<string, string>;
      PathParameterValues?: string[];
      QueryStringParameters?: Record<string, string>;
    }
    export interface InputTransformer {
      InputPathsMap?: Record<string, string>;
      InputTemplate: string;
    }
    export interface KinesisParameters {
      PartitionKeyPath: string;
    }
    export interface NetworkConfiguration {
      AwsVpcConfiguration?: AwsVpcConfiguration;
    }
    export interface PlacementConstraint {
      Expression?: string;
      Type?: string;
    }
    export interface PlacementStrategy {
      Field?: string;
      Type?: string;
    }
    export interface RedshiftDataParameters {
      Database: string;
      DbUser?: string;
      SecretManagerArn?: string;
      Sql: string;
      StatementName?: string;
      WithEvent?: boolean;
    }
    export interface RetryPolicy {
      MaximumEventAgeInSeconds?: number;
      MaximumRetryAttempts?: number;
    }
    export interface RunCommandParameters {
      RunCommandTargets: RunCommandTarget[];
    }
    export interface RunCommandTarget {
      Key: string;
      Values: string[];
    }
    export interface SageMakerPipelineParameter {
      Name: string;
      Value: string;
    }
    export interface SageMakerPipelineParameters {
      PipelineParameterList?: SageMakerPipelineParameter[];
    }
    export interface SqsParameters {
      MessageGroupId: string;
    }
    export interface Tag {
      Key?: string;
      Value?: string;
    }
    export interface Target {
      Arn: string;
      BatchParameters?: BatchParameters;
      DeadLetterConfig?: DeadLetterConfig;
      EcsParameters?: EcsParameters;
      HttpParameters?: HttpParameters;
      Id: string;
      Input?: string;
      InputPath?: string;
      InputTransformer?: InputTransformer;
      KinesisParameters?: KinesisParameters;
      RedshiftDataParameters?: RedshiftDataParameters;
      RetryPolicy?: RetryPolicy;
      RoleArn?: string;
      RunCommandParameters?: RunCommandParameters;
      SageMakerPipelineParameters?: SageMakerPipelineParameters;
      SqsParameters?: SqsParameters;
    }
  }
}
export namespace Evidently {
  export interface Experiment {
    Description?: string;
    MetricGoals: Experiment.MetricGoalObject[];
    Name: string;
    OnlineAbConfig: Experiment.OnlineAbConfigObject;
    Project: string;
    RandomizationSalt?: string;
    RemoveSegment?: boolean;
    RunningStatus?: Experiment.RunningStatusObject;
    SamplingRate?: number;
    Segment?: string;
    Tags?: Tag[];
    Treatments: Experiment.TreatmentObject[];
  }
  export namespace Experiment {
    export interface Attr {
      Arn: string;
    }
    export interface MetricGoalObject {
      DesiredChange: string;
      EntityIdKey: string;
      EventPattern?: string;
      MetricName: string;
      UnitLabel?: string;
      ValueKey: string;
    }
    export interface OnlineAbConfigObject {
      ControlTreatmentName?: string;
      TreatmentWeights?: TreatmentToWeight[];
    }
    export interface RunningStatusObject {
      AnalysisCompleteTime?: string;
      DesiredState?: string;
      Reason?: string;
      Status: string;
    }
    export interface TreatmentObject {
      Description?: string;
      Feature: string;
      TreatmentName: string;
      Variation: string;
    }
    export interface TreatmentToWeight {
      SplitWeight: number;
      Treatment: string;
    }
  }
  export interface Feature {
    DefaultVariation?: string;
    Description?: string;
    EntityOverrides?: Feature.EntityOverride[];
    EvaluationStrategy?: string;
    Name: string;
    Project: string;
    Tags?: Tag[];
    Variations: Feature.VariationObject[];
  }
  export namespace Feature {
    export interface Attr {
      Arn: string;
    }
    export interface EntityOverride {
      EntityId?: string;
      Variation?: string;
    }
    export interface VariationObject {
      BooleanValue?: boolean;
      DoubleValue?: number;
      LongValue?: number;
      StringValue?: string;
      VariationName: string;
    }
  }
  export interface Launch {
    Description?: string;
    ExecutionStatus?: Launch.ExecutionStatusObject;
    Groups: Launch.LaunchGroupObject[];
    MetricMonitors?: Launch.MetricDefinitionObject[];
    Name: string;
    Project: string;
    RandomizationSalt?: string;
    ScheduledSplitsConfig: Launch.StepConfig[];
    Tags?: Tag[];
  }
  export namespace Launch {
    export interface Attr {
      Arn: string;
    }
    export interface ExecutionStatusObject {
      DesiredState?: string;
      Reason?: string;
      Status: string;
    }
    export interface GroupToWeight {
      GroupName: string;
      SplitWeight: number;
    }
    export interface LaunchGroupObject {
      Description?: string;
      Feature: string;
      GroupName: string;
      Variation: string;
    }
    export interface MetricDefinitionObject {
      EntityIdKey: string;
      EventPattern?: string;
      MetricName: string;
      UnitLabel?: string;
      ValueKey: string;
    }
    export interface SegmentOverride {
      EvaluationOrder: number;
      Segment: string;
      Weights: GroupToWeight[];
    }
    export interface StepConfig {
      GroupWeights: GroupToWeight[];
      SegmentOverrides?: SegmentOverride[];
      StartTime: string;
    }
  }
  export interface Project {
    AppConfigResource?: Project.AppConfigResourceObject;
    DataDelivery?: Project.DataDeliveryObject;
    Description?: string;
    Name: string;
    Tags?: Tag[];
  }
  export namespace Project {
    export interface Attr {
      Arn: string;
    }
    export interface AppConfigResourceObject {
      ApplicationId: string;
      EnvironmentId: string;
    }
    export interface DataDeliveryObject {
      LogGroup?: string;
      S3?: S3Destination;
    }
    export interface S3Destination {
      BucketName: string;
      Prefix?: string;
    }
  }
  export interface Segment {
    Description?: string;
    Name: string;
    Pattern?: string;
    Tags?: Tag[];
  }
}
export namespace FIS {
  export interface ExperimentTemplate {
    Actions?: Record<string, ExperimentTemplate.ExperimentTemplateAction>;
    Description: string;
    LogConfiguration?: ExperimentTemplate.ExperimentTemplateLogConfiguration;
    RoleArn: string;
    StopConditions: ExperimentTemplate.ExperimentTemplateStopCondition[];
    Tags: Record<string, string>;
    Targets: Record<string, ExperimentTemplate.ExperimentTemplateTarget>;
  }
  export namespace ExperimentTemplate {
    export interface Attr {
      Id: string;
    }
    export interface CloudWatchLogsConfiguration {
      LogGroupArn: string;
    }
    export interface ExperimentTemplateAction {
      ActionId: string;
      Description?: string;
      Parameters?: Record<string, string>;
      StartAfter?: string[];
      Targets?: Record<string, string>;
    }
    export interface ExperimentTemplateLogConfiguration {
      CloudWatchLogsConfiguration?: any;
      LogSchemaVersion: number;
      S3Configuration?: any;
    }
    export interface ExperimentTemplateStopCondition {
      Source: string;
      Value?: string;
    }
    export interface ExperimentTemplateTarget {
      Filters?: ExperimentTemplateTargetFilter[];
      Parameters?: Record<string, string>;
      ResourceArns?: string[];
      ResourceTags?: Record<string, string>;
      ResourceType: string;
      SelectionMode: string;
    }
    export interface ExperimentTemplateTargetFilter {
      Path: string;
      Values: string[];
    }
    export interface S3Configuration {
      BucketName: string;
      Prefix?: string;
    }
  }
}
export namespace FMS {
  export interface NotificationChannel {
    SnsRoleName: string;
    SnsTopicArn: string;
  }
  export interface Policy {
    DeleteAllPolicyResources?: boolean;
    ExcludeMap?: Policy.IEMap;
    ExcludeResourceTags: boolean;
    IncludeMap?: Policy.IEMap;
    PolicyDescription?: string;
    PolicyName: string;
    RemediationEnabled: boolean;
    ResourceSetIds?: string[];
    ResourceTags?: Policy.ResourceTag[];
    ResourceType?: string;
    ResourceTypeList?: string[];
    ResourcesCleanUp?: boolean;
    SecurityServicePolicyData: Policy.SecurityServicePolicyData;
    Tags?: Policy.PolicyTag[];
  }
  export namespace Policy {
    export interface Attr {
      Arn: string;
      Id: string;
    }
    export interface IEMap {
      ACCOUNT?: string[];
      ORGUNIT?: string[];
    }
    export interface NetworkFirewallPolicy {
      FirewallDeploymentModel: string;
    }
    export interface PolicyOption {
      NetworkFirewallPolicy?: NetworkFirewallPolicy;
      ThirdPartyFirewallPolicy?: ThirdPartyFirewallPolicy;
    }
    export interface PolicyTag {
      Key: string;
      Value: string;
    }
    export interface ResourceTag {
      Key: string;
      Value?: string;
    }
    export interface SecurityServicePolicyData {
      ManagedServiceData?: string;
      PolicyOption?: PolicyOption;
      Type: string;
    }
    export interface ThirdPartyFirewallPolicy {
      FirewallDeploymentModel: string;
    }
  }
}
export namespace FSx {
  export interface DataRepositoryAssociation {
    BatchImportMetaDataOnCreate?: boolean;
    DataRepositoryPath: string;
    FileSystemId: string;
    FileSystemPath: string;
    ImportedFileChunkSize?: number;
    S3?: DataRepositoryAssociation.S3;
    Tags?: Tag[];
  }
  export namespace DataRepositoryAssociation {
    export interface Attr {
      AssociationId: string;
      ResourceARN: string;
    }
    export interface AutoExportPolicy {
      Events: string[];
    }
    export interface AutoImportPolicy {
      Events: string[];
    }
    export interface S3 {
      AutoExportPolicy?: AutoExportPolicy;
      AutoImportPolicy?: AutoImportPolicy;
    }
  }
  export interface FileSystem {
    BackupId?: string;
    FileSystemType: string;
    FileSystemTypeVersion?: string;
    KmsKeyId?: string;
    LustreConfiguration?: FileSystem.LustreConfiguration;
    OntapConfiguration?: FileSystem.OntapConfiguration;
    OpenZFSConfiguration?: FileSystem.OpenZFSConfiguration;
    SecurityGroupIds?: string[];
    StorageCapacity?: number;
    StorageType?: string;
    SubnetIds: string[];
    Tags?: Tag[];
    WindowsConfiguration?: FileSystem.WindowsConfiguration;
  }
  export namespace FileSystem {
    export interface Attr {
      DNSName: string;
      LustreMountName: string;
      ResourceARN: string;
      RootVolumeId: string;
    }
    export interface AuditLogConfiguration {
      AuditLogDestination?: string;
      FileAccessAuditLogLevel: string;
      FileShareAccessAuditLogLevel: string;
    }
    export interface ClientConfigurations {
      Clients?: string;
      Options?: string[];
    }
    export interface DiskIopsConfiguration {
      Iops?: number;
      Mode?: string;
    }
    export interface LustreConfiguration {
      AutoImportPolicy?: string;
      AutomaticBackupRetentionDays?: number;
      CopyTagsToBackups?: boolean;
      DailyAutomaticBackupStartTime?: string;
      DataCompressionType?: string;
      DeploymentType?: string;
      DriveCacheType?: string;
      ExportPath?: string;
      ImportPath?: string;
      ImportedFileChunkSize?: number;
      PerUnitStorageThroughput?: number;
      WeeklyMaintenanceStartTime?: string;
    }
    export interface NfsExports {
      ClientConfigurations?: ClientConfigurations[];
    }
    export interface OntapConfiguration {
      AutomaticBackupRetentionDays?: number;
      DailyAutomaticBackupStartTime?: string;
      DeploymentType: string;
      DiskIopsConfiguration?: DiskIopsConfiguration;
      EndpointIpAddressRange?: string;
      FsxAdminPassword?: string;
      PreferredSubnetId?: string;
      RouteTableIds?: string[];
      ThroughputCapacity?: number;
      WeeklyMaintenanceStartTime?: string;
    }
    export interface OpenZFSConfiguration {
      AutomaticBackupRetentionDays?: number;
      CopyTagsToBackups?: boolean;
      CopyTagsToVolumes?: boolean;
      DailyAutomaticBackupStartTime?: string;
      DeploymentType: string;
      DiskIopsConfiguration?: DiskIopsConfiguration;
      Options?: string[];
      RootVolumeConfiguration?: RootVolumeConfiguration;
      ThroughputCapacity?: number;
      WeeklyMaintenanceStartTime?: string;
    }
    export interface RootVolumeConfiguration {
      CopyTagsToSnapshots?: boolean;
      DataCompressionType?: string;
      NfsExports?: NfsExports[];
      ReadOnly?: boolean;
      RecordSizeKiB?: number;
      UserAndGroupQuotas?: UserAndGroupQuotas[];
    }
    export interface SelfManagedActiveDirectoryConfiguration {
      DnsIps?: string[];
      DomainName?: string;
      FileSystemAdministratorsGroup?: string;
      OrganizationalUnitDistinguishedName?: string;
      Password?: string;
      UserName?: string;
    }
    export interface UserAndGroupQuotas {
      Id?: number;
      StorageCapacityQuotaGiB?: number;
      Type?: string;
    }
    export interface WindowsConfiguration {
      ActiveDirectoryId?: string;
      Aliases?: string[];
      AuditLogConfiguration?: AuditLogConfiguration;
      AutomaticBackupRetentionDays?: number;
      CopyTagsToBackups?: boolean;
      DailyAutomaticBackupStartTime?: string;
      DeploymentType?: string;
      PreferredSubnetId?: string;
      SelfManagedActiveDirectoryConfiguration?: SelfManagedActiveDirectoryConfiguration;
      ThroughputCapacity: number;
      WeeklyMaintenanceStartTime?: string;
    }
  }
  export interface Snapshot {
    Name: string;
    Tags?: Tag[];
    VolumeId: string;
  }
  export interface StorageVirtualMachine {
    ActiveDirectoryConfiguration?: StorageVirtualMachine.ActiveDirectoryConfiguration;
    FileSystemId: string;
    Name: string;
    RootVolumeSecurityStyle?: string;
    SvmAdminPassword?: string;
    Tags?: Tag[];
  }
  export namespace StorageVirtualMachine {
    export interface Attr {
      ResourceARN: string;
      StorageVirtualMachineId: string;
      UUID: string;
    }
    export interface ActiveDirectoryConfiguration {
      NetBiosName?: string;
      SelfManagedActiveDirectoryConfiguration?: SelfManagedActiveDirectoryConfiguration;
    }
    export interface SelfManagedActiveDirectoryConfiguration {
      DnsIps?: string[];
      DomainName?: string;
      FileSystemAdministratorsGroup?: string;
      OrganizationalUnitDistinguishedName?: string;
      Password?: string;
      UserName?: string;
    }
  }
  export interface Volume {
    BackupId?: string;
    Name: string;
    OntapConfiguration?: Volume.OntapConfiguration;
    OpenZFSConfiguration?: Volume.OpenZFSConfiguration;
    Tags?: Tag[];
    VolumeType?: string;
  }
  export namespace Volume {
    export interface Attr {
      ResourceARN: string;
      UUID: string;
      VolumeId: string;
    }
    export interface ClientConfigurations {
      Clients: string;
      Options: string[];
    }
    export interface NfsExports {
      ClientConfigurations: ClientConfigurations[];
    }
    export interface OntapConfiguration {
      CopyTagsToBackups?: string;
      JunctionPath?: string;
      OntapVolumeType?: string;
      SecurityStyle?: string;
      SizeInMegabytes: string;
      SnapshotPolicy?: string;
      StorageEfficiencyEnabled?: string;
      StorageVirtualMachineId: string;
      TieringPolicy?: TieringPolicy;
    }
    export interface OpenZFSConfiguration {
      CopyTagsToSnapshots?: boolean;
      DataCompressionType?: string;
      NfsExports?: NfsExports[];
      Options?: string[];
      OriginSnapshot?: OriginSnapshot;
      ParentVolumeId: string;
      ReadOnly?: boolean;
      RecordSizeKiB?: number;
      StorageCapacityQuotaGiB?: number;
      StorageCapacityReservationGiB?: number;
      UserAndGroupQuotas?: UserAndGroupQuotas[];
    }
    export interface OriginSnapshot {
      CopyStrategy: string;
      SnapshotARN: string;
    }
    export interface TieringPolicy {
      CoolingPeriod?: number;
      Name?: string;
    }
    export interface UserAndGroupQuotas {
      Id: number;
      StorageCapacityQuotaGiB: number;
      Type: string;
    }
  }
}
export namespace FinSpace {
  export interface Environment {
    DataBundles?: string[];
    Description?: string;
    FederationMode?: string;
    FederationParameters?: Environment.FederationParameters;
    KmsKeyId?: string;
    Name: string;
    SuperuserParameters?: Environment.SuperuserParameters;
  }
  export namespace Environment {
    export interface Attr {
      AwsAccountId: string;
      DedicatedServiceAccountId: string;
      EnvironmentArn: string;
      EnvironmentId: string;
      EnvironmentUrl: string;
      SageMakerStudioDomainUrl: string;
      Status: string;
    }
    export interface FederationParameters {
      ApplicationCallBackURL?: string;
      AttributeMap?: any;
      FederationProviderName?: string;
      FederationURN?: string;
      SamlMetadataDocument?: string;
      SamlMetadataURL?: string;
    }
    export interface SuperuserParameters {
      EmailAddress?: string;
      FirstName?: string;
      LastName?: string;
    }
  }
}
export namespace Forecast {
  export interface Dataset {
    DataFrequency?: string;
    DatasetName: string;
    DatasetType: string;
    Domain: string;
    EncryptionConfig?: any;
    Schema: any;
    Tags?: Dataset.TagsItems[];
  }
  export namespace Dataset {
    export interface Attr {
      Arn: string;
    }
    export interface AttributesItems {
      AttributeName?: string;
      AttributeType?: string;
    }
    export interface EncryptionConfig {
      KmsKeyArn?: string;
      RoleArn?: string;
    }
    export interface Schema {
      Attributes?: AttributesItems[];
    }
    export interface TagsItems {
      Key: string;
      Value: string;
    }
  }
  export interface DatasetGroup {
    DatasetArns?: string[];
    DatasetGroupName: string;
    Domain: string;
    Tags?: Tag[];
  }
}
export namespace FraudDetector {
  export interface Detector {
    AssociatedModels?: Detector.Model[];
    Description?: string;
    DetectorId: string;
    DetectorVersionStatus?: string;
    EventType: Detector.EventType;
    RuleExecutionMode?: string;
    Rules: Detector.Rule[];
    Tags?: Tag[];
  }
  export namespace Detector {
    export interface Attr {
      Arn: string;
      CreatedTime: string;
      DetectorVersionId: string;
      "EventType.Arn": string;
      "EventType.CreatedTime": string;
      "EventType.LastUpdatedTime": string;
      LastUpdatedTime: string;
    }
    export interface EntityType {
      Arn?: string;
      CreatedTime?: string;
      Description?: string;
      Inline?: boolean;
      LastUpdatedTime?: string;
      Name?: string;
      Tags?: Tag[];
    }
    export interface EventType {
      Arn?: string;
      CreatedTime?: string;
      Description?: string;
      EntityTypes?: EntityType[];
      EventVariables?: EventVariable[];
      Inline?: boolean;
      Labels?: Label[];
      LastUpdatedTime?: string;
      Name?: string;
      Tags?: Tag[];
    }
    export interface EventVariable {
      Arn?: string;
      CreatedTime?: string;
      DataSource?: string;
      DataType?: string;
      DefaultValue?: string;
      Description?: string;
      Inline?: boolean;
      LastUpdatedTime?: string;
      Name?: string;
      Tags?: Tag[];
      VariableType?: string;
    }
    export interface Label {
      Arn?: string;
      CreatedTime?: string;
      Description?: string;
      Inline?: boolean;
      LastUpdatedTime?: string;
      Name?: string;
      Tags?: Tag[];
    }
    export interface Model {
      Arn?: string;
    }
    export interface Outcome {
      Arn?: string;
      CreatedTime?: string;
      Description?: string;
      Inline?: boolean;
      LastUpdatedTime?: string;
      Name?: string;
      Tags?: Tag[];
    }
    export interface Rule {
      Arn?: string;
      CreatedTime?: string;
      Description?: string;
      DetectorId?: string;
      Expression?: string;
      Language?: string;
      LastUpdatedTime?: string;
      Outcomes?: Outcome[];
      RuleId?: string;
      RuleVersion?: string;
      Tags?: Tag[];
    }
  }
  export interface EntityType {
    Description?: string;
    Name: string;
    Tags?: Tag[];
  }
  export interface EventType {
    Description?: string;
    EntityTypes: EventType.EntityType[];
    EventVariables: EventType.EventVariable[];
    Labels: EventType.Label[];
    Name: string;
    Tags?: Tag[];
  }
  export namespace EventType {
    export interface Attr {
      Arn: string;
      CreatedTime: string;
      LastUpdatedTime: string;
    }
    export interface EntityType {
      Arn?: string;
      CreatedTime?: string;
      Description?: string;
      Inline?: boolean;
      LastUpdatedTime?: string;
      Name?: string;
      Tags?: Tag[];
    }
    export interface EventVariable {
      Arn?: string;
      CreatedTime?: string;
      DataSource?: string;
      DataType?: string;
      DefaultValue?: string;
      Description?: string;
      Inline?: boolean;
      LastUpdatedTime?: string;
      Name?: string;
      Tags?: Tag[];
      VariableType?: string;
    }
    export interface Label {
      Arn?: string;
      CreatedTime?: string;
      Description?: string;
      Inline?: boolean;
      LastUpdatedTime?: string;
      Name?: string;
      Tags?: Tag[];
    }
  }
  export interface Label {
    Description?: string;
    Name: string;
    Tags?: Tag[];
  }
  export interface Outcome {
    Description?: string;
    Name: string;
    Tags?: Tag[];
  }
  export interface Variable {
    DataSource: string;
    DataType: string;
    DefaultValue: string;
    Description?: string;
    Name: string;
    Tags?: Tag[];
    VariableType?: string;
  }
}
export namespace GameLift {
  export interface Alias {
    Description?: string;
    Name: string;
    RoutingStrategy: Alias.RoutingStrategy;
  }
  export namespace Alias {
    export interface Attr {
      AliasId: string;
    }
    export interface RoutingStrategy {
      FleetId?: string;
      Message?: string;
      Type: string;
    }
  }
  export interface Build {
    Name?: string;
    OperatingSystem?: string;
    StorageLocation?: Build.StorageLocation;
    Version?: string;
  }
  export namespace Build {
    export interface Attr {
      BuildId: string;
    }
    export interface StorageLocation {
      Bucket: string;
      Key: string;
      ObjectVersion?: string;
      RoleArn: string;
    }
  }
  export interface Fleet {
    AnywhereConfiguration?: Fleet.AnywhereConfiguration;
    BuildId?: string;
    CertificateConfiguration?: Fleet.CertificateConfiguration;
    ComputeType?: string;
    Description?: string;
    DesiredEC2Instances?: number;
    EC2InboundPermissions?: Fleet.IpPermission[];
    EC2InstanceType?: string;
    FleetType?: string;
    InstanceRoleARN?: string;
    Locations?: Fleet.LocationConfiguration[];
    MaxSize?: number;
    MetricGroups?: string[];
    MinSize?: number;
    Name: string;
    NewGameSessionProtectionPolicy?: string;
    PeerVpcAwsAccountId?: string;
    PeerVpcId?: string;
    ResourceCreationLimitPolicy?: Fleet.ResourceCreationLimitPolicy;
    RuntimeConfiguration?: Fleet.RuntimeConfiguration;
    ScriptId?: string;
  }
  export namespace Fleet {
    export interface Attr {
      FleetId: string;
    }
    export interface AnywhereConfiguration {
      Cost: string;
    }
    export interface CertificateConfiguration {
      CertificateType: string;
    }
    export interface IpPermission {
      FromPort: number;
      IpRange: string;
      Protocol: string;
      ToPort: number;
    }
    export interface LocationCapacity {
      DesiredEC2Instances: number;
      MaxSize: number;
      MinSize: number;
    }
    export interface LocationConfiguration {
      Location: string;
      LocationCapacity?: LocationCapacity;
    }
    export interface ResourceCreationLimitPolicy {
      NewGameSessionsPerCreator?: number;
      PolicyPeriodInMinutes?: number;
    }
    export interface RuntimeConfiguration {
      GameSessionActivationTimeoutSeconds?: number;
      MaxConcurrentGameSessionActivations?: number;
      ServerProcesses?: ServerProcess[];
    }
    export interface ServerProcess {
      ConcurrentExecutions: number;
      LaunchPath: string;
      Parameters?: string;
    }
  }
  export interface GameServerGroup {
    AutoScalingPolicy?: GameServerGroup.AutoScalingPolicy;
    BalancingStrategy?: string;
    DeleteOption?: string;
    GameServerGroupName: string;
    GameServerProtectionPolicy?: string;
    InstanceDefinitions: GameServerGroup.InstanceDefinition[];
    LaunchTemplate: GameServerGroup.LaunchTemplate;
    MaxSize?: number;
    MinSize?: number;
    RoleArn: string;
    Tags?: Tag[];
    VpcSubnets?: string[];
  }
  export namespace GameServerGroup {
    export interface Attr {
      AutoScalingGroupArn: string;
      GameServerGroupArn: string;
    }
    export interface AutoScalingPolicy {
      EstimatedInstanceWarmup?: number;
      TargetTrackingConfiguration: TargetTrackingConfiguration;
    }
    export interface InstanceDefinition {
      InstanceType: string;
      WeightedCapacity?: string;
    }
    export interface LaunchTemplate {
      LaunchTemplateId?: string;
      LaunchTemplateName?: string;
      Version?: string;
    }
    export interface TargetTrackingConfiguration {
      TargetValue: number;
    }
  }
  export interface GameSessionQueue {
    CustomEventData?: string;
    Destinations?: GameSessionQueue.Destination[];
    FilterConfiguration?: GameSessionQueue.FilterConfiguration;
    Name: string;
    NotificationTarget?: string;
    PlayerLatencyPolicies?: GameSessionQueue.PlayerLatencyPolicy[];
    PriorityConfiguration?: GameSessionQueue.PriorityConfiguration;
    Tags?: Tag[];
    TimeoutInSeconds?: number;
  }
  export namespace GameSessionQueue {
    export interface Attr {
      Arn: string;
      Name: string;
    }
    export interface Destination {
      DestinationArn?: string;
    }
    export interface FilterConfiguration {
      AllowedLocations?: string[];
    }
    export interface PlayerLatencyPolicy {
      MaximumIndividualPlayerLatencyMilliseconds?: number;
      PolicyDurationSeconds?: number;
    }
    export interface PriorityConfiguration {
      LocationOrder?: string[];
      PriorityOrder?: string[];
    }
  }
  export interface Location {
    LocationName: string;
    Tags?: Tag[];
  }
  export interface MatchmakingConfiguration {
    AcceptanceRequired: boolean;
    AcceptanceTimeoutSeconds?: number;
    AdditionalPlayerCount?: number;
    BackfillMode?: string;
    CustomEventData?: string;
    Description?: string;
    FlexMatchMode?: string;
    GameProperties?: MatchmakingConfiguration.GameProperty[];
    GameSessionData?: string;
    GameSessionQueueArns?: string[];
    Name: string;
    NotificationTarget?: string;
    RequestTimeoutSeconds: number;
    RuleSetName: string;
    Tags?: Tag[];
  }
  export namespace MatchmakingConfiguration {
    export interface Attr {
      Arn: string;
      Name: string;
    }
    export interface GameProperty {
      Key: string;
      Value: string;
    }
  }
  export interface MatchmakingRuleSet {
    Name: string;
    RuleSetBody: string;
    Tags?: Tag[];
  }
  export interface Script {
    Name?: string;
    StorageLocation: Script.S3Location;
    Tags?: Tag[];
    Version?: string;
  }
  export namespace Script {
    export interface Attr {
      Arn: string;
      Id: string;
    }
    export interface S3Location {
      Bucket: string;
      Key: string;
      ObjectVersion?: string;
      RoleArn: string;
    }
  }
}
export namespace GlobalAccelerator {
  export interface Accelerator {
    Enabled?: boolean;
    IpAddressType?: string;
    IpAddresses?: string[];
    Name: string;
    Tags?: Tag[];
  }
  export interface EndpointGroup {
    EndpointConfigurations?: EndpointGroup.EndpointConfiguration[];
    EndpointGroupRegion: string;
    HealthCheckIntervalSeconds?: number;
    HealthCheckPath?: string;
    HealthCheckPort?: number;
    HealthCheckProtocol?: string;
    ListenerArn: string;
    PortOverrides?: EndpointGroup.PortOverride[];
    ThresholdCount?: number;
    TrafficDialPercentage?: number;
  }
  export namespace EndpointGroup {
    export interface Attr {
      EndpointGroupArn: string;
    }
    export interface EndpointConfiguration {
      ClientIPPreservationEnabled?: boolean;
      EndpointId: string;
      Weight?: number;
    }
    export interface PortOverride {
      EndpointPort: number;
      ListenerPort: number;
    }
  }
  export interface Listener {
    AcceleratorArn: string;
    ClientAffinity?: string;
    PortRanges: Listener.PortRange[];
    Protocol: string;
  }
  export namespace Listener {
    export interface Attr {
      ListenerArn: string;
    }
    export interface PortRange {
      FromPort: number;
      ToPort: number;
    }
  }
}
export namespace Glue {
  export interface Classifier {
    CsvClassifier?: Classifier.CsvClassifier;
    GrokClassifier?: Classifier.GrokClassifier;
    JsonClassifier?: Classifier.JsonClassifier;
    XMLClassifier?: Classifier.XMLClassifier;
  }
  export namespace Classifier {
    export interface Attr {}
    export interface CsvClassifier {
      AllowSingleColumn?: boolean;
      ContainsHeader?: string;
      Delimiter?: string;
      DisableValueTrimming?: boolean;
      Header?: string[];
      Name?: string;
      QuoteSymbol?: string;
    }
    export interface GrokClassifier {
      Classification: string;
      CustomPatterns?: string;
      GrokPattern: string;
      Name?: string;
    }
    export interface JsonClassifier {
      JsonPath: string;
      Name?: string;
    }
    export interface XMLClassifier {
      Classification: string;
      Name?: string;
      RowTag: string;
    }
  }
  export interface Connection {
    CatalogId: string;
    ConnectionInput: Connection.ConnectionInput;
  }
  export namespace Connection {
    export interface Attr {}
    export interface ConnectionInput {
      ConnectionProperties?: any;
      ConnectionType: string;
      Description?: string;
      MatchCriteria?: string[];
      Name?: string;
      PhysicalConnectionRequirements?: PhysicalConnectionRequirements;
    }
    export interface PhysicalConnectionRequirements {
      AvailabilityZone?: string;
      SecurityGroupIdList?: string[];
      SubnetId?: string;
    }
  }
  export interface Crawler {
    Classifiers?: string[];
    Configuration?: string;
    CrawlerSecurityConfiguration?: string;
    DatabaseName?: string;
    Description?: string;
    Name?: string;
    RecrawlPolicy?: Crawler.RecrawlPolicy;
    Role: string;
    Schedule?: Crawler.Schedule;
    SchemaChangePolicy?: Crawler.SchemaChangePolicy;
    TablePrefix?: string;
    Tags?: any;
    Targets: Crawler.Targets;
  }
  export namespace Crawler {
    export interface Attr {}
    export interface CatalogTarget {
      DatabaseName?: string;
      Tables?: string[];
    }
    export interface DynamoDBTarget {
      Path?: string;
    }
    export interface JdbcTarget {
      ConnectionName?: string;
      Exclusions?: string[];
      Path?: string;
    }
    export interface MongoDBTarget {
      ConnectionName?: string;
      Path?: string;
    }
    export interface RecrawlPolicy {
      RecrawlBehavior?: string;
    }
    export interface S3Target {
      ConnectionName?: string;
      DlqEventQueueArn?: string;
      EventQueueArn?: string;
      Exclusions?: string[];
      Path?: string;
      SampleSize?: number;
    }
    export interface Schedule {
      ScheduleExpression?: string;
    }
    export interface SchemaChangePolicy {
      DeleteBehavior?: string;
      UpdateBehavior?: string;
    }
    export interface Targets {
      CatalogTargets?: CatalogTarget[];
      DynamoDBTargets?: DynamoDBTarget[];
      JdbcTargets?: JdbcTarget[];
      MongoDBTargets?: MongoDBTarget[];
      S3Targets?: S3Target[];
    }
  }
  export interface DataCatalogEncryptionSettings {
    CatalogId: string;
    DataCatalogEncryptionSettings: DataCatalogEncryptionSettings.DataCatalogEncryptionSettings;
  }
  export namespace DataCatalogEncryptionSettings {
    export interface Attr {}
    export interface ConnectionPasswordEncryption {
      KmsKeyId?: string;
      ReturnConnectionPasswordEncrypted?: boolean;
    }
    export interface DataCatalogEncryptionSettings {
      ConnectionPasswordEncryption?: ConnectionPasswordEncryption;
      EncryptionAtRest?: EncryptionAtRest;
    }
    export interface EncryptionAtRest {
      CatalogEncryptionMode?: string;
      SseAwsKmsKeyId?: string;
    }
  }
  export interface Database {
    CatalogId: string;
    DatabaseInput: Database.DatabaseInput;
  }
  export namespace Database {
    export interface Attr {}
    export interface DataLakePrincipal {
      DataLakePrincipalIdentifier?: string;
    }
    export interface DatabaseIdentifier {
      CatalogId?: string;
      DatabaseName?: string;
    }
    export interface DatabaseInput {
      CreateTableDefaultPermissions?: PrincipalPrivileges[];
      Description?: string;
      LocationUri?: string;
      Name?: string;
      Parameters?: any;
      TargetDatabase?: DatabaseIdentifier;
    }
    export interface PrincipalPrivileges {
      Permissions?: string[];
      Principal?: DataLakePrincipal;
    }
  }
  export interface DevEndpoint {
    Arguments?: any;
    EndpointName?: string;
    ExtraJarsS3Path?: string;
    ExtraPythonLibsS3Path?: string;
    GlueVersion?: string;
    NumberOfNodes?: number;
    NumberOfWorkers?: number;
    PublicKey?: string;
    PublicKeys?: string[];
    RoleArn: string;
    SecurityConfiguration?: string;
    SecurityGroupIds?: string[];
    SubnetId?: string;
    Tags?: any;
    WorkerType?: string;
  }
  export interface Job {
    AllocatedCapacity?: number;
    Command: Job.JobCommand;
    Connections?: Job.ConnectionsList;
    DefaultArguments?: any;
    Description?: string;
    ExecutionClass?: string;
    ExecutionProperty?: Job.ExecutionProperty;
    GlueVersion?: string;
    LogUri?: string;
    MaxCapacity?: number;
    MaxRetries?: number;
    Name?: string;
    NonOverridableArguments?: any;
    NotificationProperty?: Job.NotificationProperty;
    NumberOfWorkers?: number;
    Role: string;
    SecurityConfiguration?: string;
    Tags?: any;
    Timeout?: number;
    WorkerType?: string;
  }
  export namespace Job {
    export interface Attr {}
    export interface ConnectionsList {
      Connections?: string[];
    }
    export interface ExecutionProperty {
      MaxConcurrentRuns?: number;
    }
    export interface JobCommand {
      Name?: string;
      PythonVersion?: string;
      ScriptLocation?: string;
    }
    export interface NotificationProperty {
      NotifyDelayAfter?: number;
    }
  }
  export interface MLTransform {
    Description?: string;
    GlueVersion?: string;
    InputRecordTables: MLTransform.InputRecordTables;
    MaxCapacity?: number;
    MaxRetries?: number;
    Name?: string;
    NumberOfWorkers?: number;
    Role: string;
    Tags?: any;
    Timeout?: number;
    TransformEncryption?: MLTransform.TransformEncryption;
    TransformParameters: MLTransform.TransformParameters;
    WorkerType?: string;
  }
  export namespace MLTransform {
    export interface Attr {}
    export interface FindMatchesParameters {
      AccuracyCostTradeoff?: number;
      EnforceProvidedLabels?: boolean;
      PrecisionRecallTradeoff?: number;
      PrimaryKeyColumnName: string;
    }
    export interface GlueTables {
      CatalogId?: string;
      ConnectionName?: string;
      DatabaseName: string;
      TableName: string;
    }
    export interface InputRecordTables {
      GlueTables?: GlueTables[];
    }
    export interface MLUserDataEncryption {
      KmsKeyId?: string;
      MLUserDataEncryptionMode: string;
    }
    export interface TransformEncryption {
      MLUserDataEncryption?: MLUserDataEncryption;
      TaskRunSecurityConfigurationName?: string;
    }
    export interface TransformParameters {
      FindMatchesParameters?: FindMatchesParameters;
      TransformType: string;
    }
  }
  export interface Partition {
    CatalogId: string;
    DatabaseName: string;
    PartitionInput: Partition.PartitionInput;
    TableName: string;
  }
  export namespace Partition {
    export interface Attr {}
    export interface Column {
      Comment?: string;
      Name: string;
      Type?: string;
    }
    export interface Order {
      Column: string;
      SortOrder?: number;
    }
    export interface PartitionInput {
      Parameters?: any;
      StorageDescriptor?: StorageDescriptor;
      Values: string[];
    }
    export interface SchemaId {
      RegistryName?: string;
      SchemaArn?: string;
      SchemaName?: string;
    }
    export interface SchemaReference {
      SchemaId?: SchemaId;
      SchemaVersionId?: string;
      SchemaVersionNumber?: number;
    }
    export interface SerdeInfo {
      Name?: string;
      Parameters?: any;
      SerializationLibrary?: string;
    }
    export interface SkewedInfo {
      SkewedColumnNames?: string[];
      SkewedColumnValueLocationMaps?: any;
      SkewedColumnValues?: string[];
    }
    export interface StorageDescriptor {
      BucketColumns?: string[];
      Columns?: Column[];
      Compressed?: boolean;
      InputFormat?: string;
      Location?: string;
      NumberOfBuckets?: number;
      OutputFormat?: string;
      Parameters?: any;
      SchemaReference?: SchemaReference;
      SerdeInfo?: SerdeInfo;
      SkewedInfo?: SkewedInfo;
      SortColumns?: Order[];
      StoredAsSubDirectories?: boolean;
    }
  }
  export interface Registry {
    Description?: string;
    Name: string;
    Tags?: Tag[];
  }
  export interface Schema {
    CheckpointVersion?: Schema.SchemaVersion;
    Compatibility: string;
    DataFormat: string;
    Description?: string;
    Name: string;
    Registry?: Schema.Registry;
    SchemaDefinition: string;
    Tags?: Tag[];
  }
  export namespace Schema {
    export interface Attr {
      Arn: string;
      InitialSchemaVersionId: string;
    }
    export interface Registry {
      Arn?: string;
      Name?: string;
    }
    export interface SchemaVersion {
      IsLatest?: boolean;
      VersionNumber?: number;
    }
  }
  export interface SchemaVersion {
    Schema: SchemaVersion.Schema;
    SchemaDefinition: string;
  }
  export namespace SchemaVersion {
    export interface Attr {
      VersionId: string;
    }
    export interface Schema {
      RegistryName?: string;
      SchemaArn?: string;
      SchemaName?: string;
    }
  }
  export interface SchemaVersionMetadata {
    Key: string;
    SchemaVersionId: string;
    Value: string;
  }
  export interface SecurityConfiguration {
    EncryptionConfiguration: SecurityConfiguration.EncryptionConfiguration;
    Name: string;
  }
  export namespace SecurityConfiguration {
    export interface Attr {}
    export interface CloudWatchEncryption {
      CloudWatchEncryptionMode?: string;
      KmsKeyArn?: string;
    }
    export interface EncryptionConfiguration {
      CloudWatchEncryption?: CloudWatchEncryption;
      JobBookmarksEncryption?: JobBookmarksEncryption;
      S3Encryptions?: S3Encryptions;
    }
    export interface JobBookmarksEncryption {
      JobBookmarksEncryptionMode?: string;
      KmsKeyArn?: string;
    }
    export interface S3Encryption {
      KmsKeyArn?: string;
      S3EncryptionMode?: string;
    }
    export interface S3Encryptions {}
  }
  export interface Table {
    CatalogId: string;
    DatabaseName: string;
    TableInput: Table.TableInput;
  }
  export namespace Table {
    export interface Attr {}
    export interface Column {
      Comment?: string;
      Name: string;
      Type?: string;
    }
    export interface Order {
      Column: string;
      SortOrder: number;
    }
    export interface SchemaId {
      RegistryName?: string;
      SchemaArn?: string;
      SchemaName?: string;
    }
    export interface SchemaReference {
      SchemaId?: SchemaId;
      SchemaVersionId?: string;
      SchemaVersionNumber?: number;
    }
    export interface SerdeInfo {
      Name?: string;
      Parameters?: any;
      SerializationLibrary?: string;
    }
    export interface SkewedInfo {
      SkewedColumnNames?: string[];
      SkewedColumnValueLocationMaps?: any;
      SkewedColumnValues?: string[];
    }
    export interface StorageDescriptor {
      BucketColumns?: string[];
      Columns?: Column[];
      Compressed?: boolean;
      InputFormat?: string;
      Location?: string;
      NumberOfBuckets?: number;
      OutputFormat?: string;
      Parameters?: any;
      SchemaReference?: SchemaReference;
      SerdeInfo?: SerdeInfo;
      SkewedInfo?: SkewedInfo;
      SortColumns?: Order[];
      StoredAsSubDirectories?: boolean;
    }
    export interface TableIdentifier {
      CatalogId?: string;
      DatabaseName?: string;
      Name?: string;
    }
    export interface TableInput {
      Description?: string;
      Name?: string;
      Owner?: string;
      Parameters?: any;
      PartitionKeys?: Column[];
      Retention?: number;
      StorageDescriptor?: StorageDescriptor;
      TableType?: string;
      TargetTable?: TableIdentifier;
      ViewExpandedText?: string;
      ViewOriginalText?: string;
    }
  }
  export interface Trigger {
    Actions: Trigger.Action[];
    Description?: string;
    EventBatchingCondition?: Trigger.EventBatchingCondition;
    Name?: string;
    Predicate?: Trigger.Predicate;
    Schedule?: string;
    StartOnCreation?: boolean;
    Tags?: any;
    Type: string;
    WorkflowName?: string;
  }
  export namespace Trigger {
    export interface Attr {}
    export interface Action {
      Arguments?: any;
      CrawlerName?: string;
      JobName?: string;
      NotificationProperty?: NotificationProperty;
      SecurityConfiguration?: string;
      Timeout?: number;
    }
    export interface Condition {
      CrawlState?: string;
      CrawlerName?: string;
      JobName?: string;
      LogicalOperator?: string;
      State?: string;
    }
    export interface EventBatchingCondition {
      BatchSize: number;
      BatchWindow?: number;
    }
    export interface NotificationProperty {
      NotifyDelayAfter?: number;
    }
    export interface Predicate {
      Conditions?: Condition[];
      Logical?: string;
    }
  }
  export interface Workflow {
    DefaultRunProperties?: any;
    Description?: string;
    MaxConcurrentRuns?: number;
    Name?: string;
    Tags?: any;
  }
}
export namespace Grafana {
  export interface Workspace {
    AccountAccessType?: string;
    AuthenticationProviders?: string[];
    ClientToken?: string;
    DataSources?: string[];
    Description?: string;
    Name?: string;
    NotificationDestinations?: string[];
    OrganizationRoleName?: string;
    OrganizationalUnits?: string[];
    PermissionType?: string;
    RoleArn?: string;
    SamlConfiguration?: Workspace.SamlConfiguration;
    StackSetName?: string;
    VpcConfiguration?: Workspace.VpcConfiguration;
  }
  export namespace Workspace {
    export interface Attr {
      CreationTimestamp: string;
      Endpoint: string;
      GrafanaVersion: string;
      Id: string;
      ModificationTimestamp: string;
      SamlConfigurationStatus: string;
      SsoClientId: string;
      Status: string;
    }
    export interface AssertionAttributes {
      Email?: string;
      Groups?: string;
      Login?: string;
      Name?: string;
      Org?: string;
      Role?: string;
    }
    export interface IdpMetadata {
      Url?: string;
      Xml?: string;
    }
    export interface RoleValues {
      Admin?: string[];
      Editor?: string[];
    }
    export interface SamlConfiguration {
      AllowedOrganizations?: string[];
      AssertionAttributes?: AssertionAttributes;
      IdpMetadata: IdpMetadata;
      LoginValidityDuration?: number;
      RoleValues?: RoleValues;
    }
    export interface VpcConfiguration {
      SecurityGroupIds: string[];
      SubnetIds: string[];
    }
  }
}
export namespace Greengrass {
  export interface ConnectorDefinition {
    InitialVersion?: ConnectorDefinition.ConnectorDefinitionVersion;
    Name: string;
    Tags?: any;
  }
  export namespace ConnectorDefinition {
    export interface Attr {
      Arn: string;
      Id: string;
      LatestVersionArn: string;
      Name: string;
    }
    export interface Connector {
      ConnectorArn: string;
      Id: string;
      Parameters?: any;
    }
    export interface ConnectorDefinitionVersion {
      Connectors: Connector[];
    }
  }
  export interface ConnectorDefinitionVersion {
    ConnectorDefinitionId: string;
    Connectors: ConnectorDefinitionVersion.Connector[];
  }
  export namespace ConnectorDefinitionVersion {
    export interface Attr {}
    export interface Connector {
      ConnectorArn: string;
      Id: string;
      Parameters?: any;
    }
  }
  export interface CoreDefinition {
    InitialVersion?: CoreDefinition.CoreDefinitionVersion;
    Name: string;
    Tags?: any;
  }
  export namespace CoreDefinition {
    export interface Attr {
      Arn: string;
      Id: string;
      LatestVersionArn: string;
      Name: string;
    }
    export interface Core {
      CertificateArn: string;
      Id: string;
      SyncShadow?: boolean;
      ThingArn: string;
    }
    export interface CoreDefinitionVersion {
      Cores: Core[];
    }
  }
  export interface CoreDefinitionVersion {
    CoreDefinitionId: string;
    Cores: CoreDefinitionVersion.Core[];
  }
  export namespace CoreDefinitionVersion {
    export interface Attr {}
    export interface Core {
      CertificateArn: string;
      Id: string;
      SyncShadow?: boolean;
      ThingArn: string;
    }
  }
  export interface DeviceDefinition {
    InitialVersion?: DeviceDefinition.DeviceDefinitionVersion;
    Name: string;
    Tags?: any;
  }
  export namespace DeviceDefinition {
    export interface Attr {
      Arn: string;
      Id: string;
      LatestVersionArn: string;
      Name: string;
    }
    export interface Device {
      CertificateArn: string;
      Id: string;
      SyncShadow?: boolean;
      ThingArn: string;
    }
    export interface DeviceDefinitionVersion {
      Devices: Device[];
    }
  }
  export interface DeviceDefinitionVersion {
    DeviceDefinitionId: string;
    Devices: DeviceDefinitionVersion.Device[];
  }
  export namespace DeviceDefinitionVersion {
    export interface Attr {}
    export interface Device {
      CertificateArn: string;
      Id: string;
      SyncShadow?: boolean;
      ThingArn: string;
    }
  }
  export interface FunctionDefinition {
    InitialVersion?: FunctionDefinition.FunctionDefinitionVersion;
    Name: string;
    Tags?: any;
  }
  export namespace FunctionDefinition {
    export interface Attr {
      Arn: string;
      Id: string;
      LatestVersionArn: string;
      Name: string;
    }
    export interface DefaultConfig {
      Execution: Execution;
    }
    export interface Environment {
      AccessSysfs?: boolean;
      Execution?: Execution;
      ResourceAccessPolicies?: ResourceAccessPolicy[];
      Variables?: any;
    }
    export interface Execution {
      IsolationMode?: string;
      RunAs?: RunAs;
    }
    export interface Function {
      FunctionArn: string;
      FunctionConfiguration: FunctionConfiguration;
      Id: string;
    }
    export interface FunctionConfiguration {
      EncodingType?: string;
      Environment?: Environment;
      ExecArgs?: string;
      Executable?: string;
      MemorySize?: number;
      Pinned?: boolean;
      Timeout?: number;
    }
    export interface FunctionDefinitionVersion {
      DefaultConfig?: DefaultConfig;
      Functions: Function[];
    }
    export interface ResourceAccessPolicy {
      Permission?: string;
      ResourceId: string;
    }
    export interface RunAs {
      Gid?: number;
      Uid?: number;
    }
  }
  export interface FunctionDefinitionVersion {
    DefaultConfig?: FunctionDefinitionVersion.DefaultConfig;
    FunctionDefinitionId: string;
    Functions: FunctionDefinitionVersion.Function[];
  }
  export namespace FunctionDefinitionVersion {
    export interface Attr {}
    export interface DefaultConfig {
      Execution: Execution;
    }
    export interface Environment {
      AccessSysfs?: boolean;
      Execution?: Execution;
      ResourceAccessPolicies?: ResourceAccessPolicy[];
      Variables?: any;
    }
    export interface Execution {
      IsolationMode?: string;
      RunAs?: RunAs;
    }
    export interface Function {
      FunctionArn: string;
      FunctionConfiguration: FunctionConfiguration;
      Id: string;
    }
    export interface FunctionConfiguration {
      EncodingType?: string;
      Environment?: Environment;
      ExecArgs?: string;
      Executable?: string;
      MemorySize?: number;
      Pinned?: boolean;
      Timeout?: number;
    }
    export interface ResourceAccessPolicy {
      Permission?: string;
      ResourceId: string;
    }
    export interface RunAs {
      Gid?: number;
      Uid?: number;
    }
  }
  export interface Group {
    InitialVersion?: Group.GroupVersion;
    Name: string;
    RoleArn?: string;
    Tags?: any;
  }
  export namespace Group {
    export interface Attr {
      Arn: string;
      Id: string;
      LatestVersionArn: string;
      Name: string;
      RoleArn: string;
      RoleAttachedAt: string;
    }
    export interface GroupVersion {
      ConnectorDefinitionVersionArn?: string;
      CoreDefinitionVersionArn?: string;
      DeviceDefinitionVersionArn?: string;
      FunctionDefinitionVersionArn?: string;
      LoggerDefinitionVersionArn?: string;
      ResourceDefinitionVersionArn?: string;
      SubscriptionDefinitionVersionArn?: string;
    }
  }
  export interface GroupVersion {
    ConnectorDefinitionVersionArn?: string;
    CoreDefinitionVersionArn?: string;
    DeviceDefinitionVersionArn?: string;
    FunctionDefinitionVersionArn?: string;
    GroupId: string;
    LoggerDefinitionVersionArn?: string;
    ResourceDefinitionVersionArn?: string;
    SubscriptionDefinitionVersionArn?: string;
  }
  export interface LoggerDefinition {
    InitialVersion?: LoggerDefinition.LoggerDefinitionVersion;
    Name: string;
    Tags?: any;
  }
  export namespace LoggerDefinition {
    export interface Attr {
      Arn: string;
      Id: string;
      LatestVersionArn: string;
      Name: string;
    }
    export interface Logger {
      Component: string;
      Id: string;
      Level: string;
      Space?: number;
      Type: string;
    }
    export interface LoggerDefinitionVersion {
      Loggers: Logger[];
    }
  }
  export interface LoggerDefinitionVersion {
    LoggerDefinitionId: string;
    Loggers: LoggerDefinitionVersion.Logger[];
  }
  export namespace LoggerDefinitionVersion {
    export interface Attr {}
    export interface Logger {
      Component: string;
      Id: string;
      Level: string;
      Space?: number;
      Type: string;
    }
  }
  export interface ResourceDefinition {
    InitialVersion?: ResourceDefinition.ResourceDefinitionVersion;
    Name: string;
    Tags?: any;
  }
  export namespace ResourceDefinition {
    export interface Attr {
      Arn: string;
      Id: string;
      LatestVersionArn: string;
      Name: string;
    }
    export interface GroupOwnerSetting {
      AutoAddGroupOwner: boolean;
      GroupOwner?: string;
    }
    export interface LocalDeviceResourceData {
      GroupOwnerSetting?: GroupOwnerSetting;
      SourcePath: string;
    }
    export interface LocalVolumeResourceData {
      DestinationPath: string;
      GroupOwnerSetting?: GroupOwnerSetting;
      SourcePath: string;
    }
    export interface ResourceDataContainer {
      LocalDeviceResourceData?: LocalDeviceResourceData;
      LocalVolumeResourceData?: LocalVolumeResourceData;
      S3MachineLearningModelResourceData?: S3MachineLearningModelResourceData;
      SageMakerMachineLearningModelResourceData?: SageMakerMachineLearningModelResourceData;
      SecretsManagerSecretResourceData?: SecretsManagerSecretResourceData;
    }
    export interface ResourceDefinitionVersion {
      Resources: ResourceInstance[];
    }
    export interface ResourceDownloadOwnerSetting {
      GroupOwner: string;
      GroupPermission: string;
    }
    export interface ResourceInstance {
      Id: string;
      Name: string;
      ResourceDataContainer: ResourceDataContainer;
    }
    export interface S3MachineLearningModelResourceData {
      DestinationPath: string;
      OwnerSetting?: ResourceDownloadOwnerSetting;
      S3Uri: string;
    }
    export interface SageMakerMachineLearningModelResourceData {
      DestinationPath: string;
      OwnerSetting?: ResourceDownloadOwnerSetting;
      SageMakerJobArn: string;
    }
    export interface SecretsManagerSecretResourceData {
      ARN: string;
      AdditionalStagingLabelsToDownload?: string[];
    }
  }
  export interface ResourceDefinitionVersion {
    ResourceDefinitionId: string;
    Resources: ResourceDefinitionVersion.ResourceInstance[];
  }
  export namespace ResourceDefinitionVersion {
    export interface Attr {}
    export interface GroupOwnerSetting {
      AutoAddGroupOwner: boolean;
      GroupOwner?: string;
    }
    export interface LocalDeviceResourceData {
      GroupOwnerSetting?: GroupOwnerSetting;
      SourcePath: string;
    }
    export interface LocalVolumeResourceData {
      DestinationPath: string;
      GroupOwnerSetting?: GroupOwnerSetting;
      SourcePath: string;
    }
    export interface ResourceDataContainer {
      LocalDeviceResourceData?: LocalDeviceResourceData;
      LocalVolumeResourceData?: LocalVolumeResourceData;
      S3MachineLearningModelResourceData?: S3MachineLearningModelResourceData;
      SageMakerMachineLearningModelResourceData?: SageMakerMachineLearningModelResourceData;
      SecretsManagerSecretResourceData?: SecretsManagerSecretResourceData;
    }
    export interface ResourceDownloadOwnerSetting {
      GroupOwner: string;
      GroupPermission: string;
    }
    export interface ResourceInstance {
      Id: string;
      Name: string;
      ResourceDataContainer: ResourceDataContainer;
    }
    export interface S3MachineLearningModelResourceData {
      DestinationPath: string;
      OwnerSetting?: ResourceDownloadOwnerSetting;
      S3Uri: string;
    }
    export interface SageMakerMachineLearningModelResourceData {
      DestinationPath: string;
      OwnerSetting?: ResourceDownloadOwnerSetting;
      SageMakerJobArn: string;
    }
    export interface SecretsManagerSecretResourceData {
      ARN: string;
      AdditionalStagingLabelsToDownload?: string[];
    }
  }
  export interface SubscriptionDefinition {
    InitialVersion?: SubscriptionDefinition.SubscriptionDefinitionVersion;
    Name: string;
    Tags?: any;
  }
  export namespace SubscriptionDefinition {
    export interface Attr {
      Arn: string;
      Id: string;
      LatestVersionArn: string;
      Name: string;
    }
    export interface Subscription {
      Id: string;
      Source: string;
      Subject: string;
      Target: string;
    }
    export interface SubscriptionDefinitionVersion {
      Subscriptions: Subscription[];
    }
  }
  export interface SubscriptionDefinitionVersion {
    SubscriptionDefinitionId: string;
    Subscriptions: SubscriptionDefinitionVersion.Subscription[];
  }
  export namespace SubscriptionDefinitionVersion {
    export interface Attr {}
    export interface Subscription {
      Id: string;
      Source: string;
      Subject: string;
      Target: string;
    }
  }
}
export namespace GreengrassV2 {
  export interface ComponentVersion {
    InlineRecipe?: string;
    LambdaFunction?: ComponentVersion.LambdaFunctionRecipeSource;
    Tags?: Record<string, string>;
  }
  export namespace ComponentVersion {
    export interface Attr {
      Arn: string;
      ComponentName: string;
      ComponentVersion: string;
    }
    export interface ComponentDependencyRequirement {
      DependencyType?: string;
      VersionRequirement?: string;
    }
    export interface ComponentPlatform {
      Attributes?: Record<string, string>;
      Name?: string;
    }
    export interface LambdaContainerParams {
      Devices?: LambdaDeviceMount[];
      MemorySizeInKB?: number;
      MountROSysfs?: boolean;
      Volumes?: LambdaVolumeMount[];
    }
    export interface LambdaDeviceMount {
      AddGroupOwner?: boolean;
      Path?: string;
      Permission?: string;
    }
    export interface LambdaEventSource {
      Topic?: string;
      Type?: string;
    }
    export interface LambdaExecutionParameters {
      EnvironmentVariables?: Record<string, string>;
      EventSources?: LambdaEventSource[];
      ExecArgs?: string[];
      InputPayloadEncodingType?: string;
      LinuxProcessParams?: LambdaLinuxProcessParams;
      MaxIdleTimeInSeconds?: number;
      MaxInstancesCount?: number;
      MaxQueueSize?: number;
      Pinned?: boolean;
      StatusTimeoutInSeconds?: number;
      TimeoutInSeconds?: number;
    }
    export interface LambdaFunctionRecipeSource {
      ComponentDependencies?: Record<string, ComponentDependencyRequirement>;
      ComponentLambdaParameters?: LambdaExecutionParameters;
      ComponentName?: string;
      ComponentPlatforms?: ComponentPlatform[];
      ComponentVersion?: string;
      LambdaArn?: string;
    }
    export interface LambdaLinuxProcessParams {
      ContainerParams?: LambdaContainerParams;
      IsolationMode?: string;
    }
    export interface LambdaVolumeMount {
      AddGroupOwner?: boolean;
      DestinationPath?: string;
      Permission?: string;
      SourcePath?: string;
    }
  }
  export interface Deployment {
    Components?: Record<string, Deployment.ComponentDeploymentSpecification>;
    DeploymentName?: string;
    DeploymentPolicies?: Deployment.DeploymentPolicies;
    IotJobConfiguration?: Deployment.DeploymentIoTJobConfiguration;
    Tags?: Record<string, string>;
    TargetArn: string;
  }
  export namespace Deployment {
    export interface Attr {
      DeploymentId: string;
    }
    export interface ComponentConfigurationUpdate {
      Merge?: string;
      Reset?: string[];
    }
    export interface ComponentDeploymentSpecification {
      ComponentVersion?: string;
      ConfigurationUpdate?: ComponentConfigurationUpdate;
      RunWith?: ComponentRunWith;
    }
    export interface ComponentRunWith {
      PosixUser?: string;
      SystemResourceLimits?: SystemResourceLimits;
      WindowsUser?: string;
    }
    export interface DeploymentComponentUpdatePolicy {
      Action?: string;
      TimeoutInSeconds?: number;
    }
    export interface DeploymentConfigurationValidationPolicy {
      TimeoutInSeconds?: number;
    }
    export interface DeploymentIoTJobConfiguration {
      AbortConfig?: IoTJobAbortConfig;
      JobExecutionsRolloutConfig?: IoTJobExecutionsRolloutConfig;
      TimeoutConfig?: IoTJobTimeoutConfig;
    }
    export interface DeploymentPolicies {
      ComponentUpdatePolicy?: DeploymentComponentUpdatePolicy;
      ConfigurationValidationPolicy?: DeploymentConfigurationValidationPolicy;
      FailureHandlingPolicy?: string;
    }
    export interface IoTJobAbortConfig {
      CriteriaList: IoTJobAbortCriteria[];
    }
    export interface IoTJobAbortCriteria {
      Action: string;
      FailureType: string;
      MinNumberOfExecutedThings: number;
      ThresholdPercentage: number;
    }
    export interface IoTJobExecutionsRolloutConfig {
      ExponentialRate?: IoTJobExponentialRolloutRate;
      MaximumPerMinute?: number;
    }
    export interface IoTJobExponentialRolloutRate {
      BaseRatePerMinute: number;
      IncrementFactor: number;
      RateIncreaseCriteria: IoTJobRateIncreaseCriteria;
    }
    export interface IoTJobRateIncreaseCriteria {}
    export interface IoTJobTimeoutConfig {
      InProgressTimeoutInMinutes?: number;
    }
    export interface SystemResourceLimits {
      Cpus?: number;
      Memory?: number;
    }
  }
}
export namespace GroundStation {
  export interface Config {
    ConfigData: Config.ConfigData;
    Name: string;
    Tags?: Tag[];
  }
  export namespace Config {
    export interface Attr {
      Arn: string;
      Id: string;
      Type: string;
    }
    export interface AntennaDownlinkConfig {
      SpectrumConfig?: SpectrumConfig;
    }
    export interface AntennaDownlinkDemodDecodeConfig {
      DecodeConfig?: DecodeConfig;
      DemodulationConfig?: DemodulationConfig;
      SpectrumConfig?: SpectrumConfig;
    }
    export interface AntennaUplinkConfig {
      SpectrumConfig?: UplinkSpectrumConfig;
      TargetEirp?: Eirp;
      TransmitDisabled?: boolean;
    }
    export interface ConfigData {
      AntennaDownlinkConfig?: AntennaDownlinkConfig;
      AntennaDownlinkDemodDecodeConfig?: AntennaDownlinkDemodDecodeConfig;
      AntennaUplinkConfig?: AntennaUplinkConfig;
      DataflowEndpointConfig?: DataflowEndpointConfig;
      S3RecordingConfig?: S3RecordingConfig;
      TrackingConfig?: TrackingConfig;
      UplinkEchoConfig?: UplinkEchoConfig;
    }
    export interface DataflowEndpointConfig {
      DataflowEndpointName?: string;
      DataflowEndpointRegion?: string;
    }
    export interface DecodeConfig {
      UnvalidatedJSON?: string;
    }
    export interface DemodulationConfig {
      UnvalidatedJSON?: string;
    }
    export interface Eirp {
      Units?: string;
      Value?: number;
    }
    export interface Frequency {
      Units?: string;
      Value?: number;
    }
    export interface FrequencyBandwidth {
      Units?: string;
      Value?: number;
    }
    export interface S3RecordingConfig {
      BucketArn?: string;
      Prefix?: string;
      RoleArn?: string;
    }
    export interface SpectrumConfig {
      Bandwidth?: FrequencyBandwidth;
      CenterFrequency?: Frequency;
      Polarization?: string;
    }
    export interface TrackingConfig {
      Autotrack?: string;
    }
    export interface UplinkEchoConfig {
      AntennaUplinkConfigArn?: string;
      Enabled?: boolean;
    }
    export interface UplinkSpectrumConfig {
      CenterFrequency?: Frequency;
      Polarization?: string;
    }
  }
  export interface DataflowEndpointGroup {
    EndpointDetails: DataflowEndpointGroup.EndpointDetails[];
    Tags?: Tag[];
  }
  export namespace DataflowEndpointGroup {
    export interface Attr {
      Arn: string;
      Id: string;
    }
    export interface DataflowEndpoint {
      Address?: SocketAddress;
      Mtu?: number;
      Name?: string;
    }
    export interface EndpointDetails {
      Endpoint?: DataflowEndpoint;
      SecurityDetails?: SecurityDetails;
    }
    export interface SecurityDetails {
      RoleArn?: string;
      SecurityGroupIds?: string[];
      SubnetIds?: string[];
    }
    export interface SocketAddress {
      Name?: string;
      Port?: number;
    }
  }
  export interface MissionProfile {
    ContactPostPassDurationSeconds?: number;
    ContactPrePassDurationSeconds?: number;
    DataflowEdges: MissionProfile.DataflowEdge[];
    MinimumViableContactDurationSeconds: number;
    Name: string;
    Tags?: Tag[];
    TrackingConfigArn: string;
  }
  export namespace MissionProfile {
    export interface Attr {
      Arn: string;
      Id: string;
      Region: string;
    }
    export interface DataflowEdge {
      Destination?: string;
      Source?: string;
    }
  }
}
export namespace GuardDuty {
  export interface Detector {
    DataSources?: Detector.CFNDataSourceConfigurations;
    Enable: boolean;
    FindingPublishingFrequency?: string;
    Tags?: Tag[];
  }
  export namespace Detector {
    export interface Attr {}
    export interface CFNDataSourceConfigurations {
      Kubernetes?: CFNKubernetesConfiguration;
      MalwareProtection?: CFNMalwareProtectionConfiguration;
      S3Logs?: CFNS3LogsConfiguration;
    }
    export interface CFNKubernetesAuditLogsConfiguration {
      Enable?: boolean;
    }
    export interface CFNKubernetesConfiguration {
      AuditLogs?: CFNKubernetesAuditLogsConfiguration;
    }
    export interface CFNMalwareProtectionConfiguration {
      ScanEc2InstanceWithFindings?: CFNScanEc2InstanceWithFindingsConfiguration;
    }
    export interface CFNS3LogsConfiguration {
      Enable?: boolean;
    }
    export interface CFNScanEc2InstanceWithFindingsConfiguration {
      EbsVolumes?: boolean;
    }
  }
  export interface Filter {
    Action: string;
    Description: string;
    DetectorId: string;
    FindingCriteria: Filter.FindingCriteria;
    Name: string;
    Rank: number;
    Tags?: Tag[];
  }
  export namespace Filter {
    export interface Attr {}
    export interface Condition {
      Eq?: string[];
      Equals?: string[];
      GreaterThan?: number;
      GreaterThanOrEqual?: number;
      Gt?: number;
      Gte?: number;
      LessThan?: number;
      LessThanOrEqual?: number;
      Lt?: number;
      Lte?: number;
      Neq?: string[];
      NotEquals?: string[];
    }
    export interface FindingCriteria {
      Criterion?: any;
      ItemType?: Condition;
    }
  }
  export interface IPSet {
    Activate: boolean;
    DetectorId: string;
    Format: string;
    Location: string;
    Name?: string;
    Tags?: Tag[];
  }
  export interface Master {
    DetectorId: string;
    InvitationId?: string;
    MasterId: string;
  }
  export interface Member {
    DetectorId: string;
    DisableEmailNotification?: boolean;
    Email: string;
    MemberId: string;
    Message?: string;
    Status?: string;
  }
  export interface ThreatIntelSet {
    Activate: boolean;
    DetectorId: string;
    Format: string;
    Location: string;
    Name?: string;
    Tags?: Tag[];
  }
}
export namespace HealthLake {
  export interface FHIRDatastore {
    DatastoreName?: string;
    DatastoreTypeVersion: string;
    PreloadDataConfig?: FHIRDatastore.PreloadDataConfig;
    SseConfiguration?: FHIRDatastore.SseConfiguration;
    Tags?: Tag[];
  }
  export namespace FHIRDatastore {
    export interface Attr {
      "CreatedAt.Nanos": number;
      "CreatedAt.Seconds": string;
      DatastoreArn: string;
      DatastoreEndpoint: string;
      DatastoreId: string;
      DatastoreStatus: string;
    }
    export interface CreatedAt {
      Nanos: number;
      Seconds: string;
    }
    export interface KmsEncryptionConfig {
      CmkType: string;
      KmsKeyId?: string;
    }
    export interface PreloadDataConfig {
      PreloadDataType: string;
    }
    export interface SseConfiguration {
      KmsEncryptionConfig: KmsEncryptionConfig;
    }
  }
}
export namespace IAM {
  export interface AccessKey {
    Serial?: number;
    Status?: string;
    UserName: string;
  }
  export interface Group {
    GroupName?: string;
    ManagedPolicyArns?: string[];
    Path?: string;
    Policies?: Group.Policy[];
  }
  export namespace Group {
    export interface Attr {
      Arn: string;
    }
    export interface Policy {
      PolicyDocument: any;
      PolicyName: string;
    }
  }
  export interface InstanceProfile {
    InstanceProfileName?: string;
    Path?: string;
    Roles: string[];
  }
  export interface ManagedPolicy {
    Description?: string;
    Groups?: string[];
    ManagedPolicyName?: string;
    Path?: string;
    PolicyDocument: any;
    Roles?: string[];
    Users?: string[];
  }
  export interface OIDCProvider {
    ClientIdList?: string[];
    Tags?: Tag[];
    ThumbprintList: string[];
    Url?: string;
  }
  export interface Policy {
    Groups?: string[];
    PolicyDocument: any;
    PolicyName: string;
    Roles?: string[];
    Users?: string[];
  }
  export interface Role {
    AssumeRolePolicyDocument: any;
    Description?: string;
    ManagedPolicyArns?: string[];
    MaxSessionDuration?: number;
    Path?: string;
    PermissionsBoundary?: string;
    Policies?: Role.Policy[];
    RoleName?: string;
    Tags?: Tag[];
  }
  export namespace Role {
    export interface Attr {
      Arn: string;
      RoleId: string;
    }
    export interface Policy {
      PolicyDocument: any;
      PolicyName: string;
    }
  }
  export interface SAMLProvider {
    Name?: string;
    SamlMetadataDocument: string;
    Tags?: Tag[];
  }
  export interface ServerCertificate {
    CertificateBody?: string;
    CertificateChain?: string;
    Path?: string;
    PrivateKey?: string;
    ServerCertificateName?: string;
    Tags?: Tag[];
  }
  export interface ServiceLinkedRole {
    AWSServiceName: string;
    CustomSuffix?: string;
    Description?: string;
  }
  export interface User {
    Groups?: string[];
    LoginProfile?: User.LoginProfile;
    ManagedPolicyArns?: string[];
    Path?: string;
    PermissionsBoundary?: string;
    Policies?: User.Policy[];
    Tags?: Tag[];
    UserName?: string;
  }
  export namespace User {
    export interface Attr {
      Arn: string;
    }
    export interface LoginProfile {
      Password: string;
      PasswordResetRequired?: boolean;
    }
    export interface Policy {
      PolicyDocument: any;
      PolicyName: string;
    }
  }
  export interface UserToGroupAddition {
    GroupName: string;
    Users: string[];
  }
  export interface VirtualMFADevice {
    Path?: string;
    Tags?: Tag[];
    Users: string[];
    VirtualMfaDeviceName?: string;
  }
}
export namespace IVS {
  export interface Channel {
    Authorized?: boolean;
    LatencyMode?: string;
    Name?: string;
    RecordingConfigurationArn?: string;
    Tags?: Tag[];
    Type?: string;
  }
  export interface PlaybackKeyPair {
    Name?: string;
    PublicKeyMaterial?: string;
    Tags?: Tag[];
  }
  export interface RecordingConfiguration {
    DestinationConfiguration: RecordingConfiguration.DestinationConfiguration;
    Name?: string;
    RecordingReconnectWindowSeconds?: number;
    Tags?: Tag[];
    ThumbnailConfiguration?: RecordingConfiguration.ThumbnailConfiguration;
  }
  export namespace RecordingConfiguration {
    export interface Attr {
      Arn: string;
      State: string;
    }
    export interface DestinationConfiguration {
      S3: S3DestinationConfiguration;
    }
    export interface S3DestinationConfiguration {
      BucketName: string;
    }
    export interface ThumbnailConfiguration {
      RecordingMode: string;
      TargetIntervalSeconds?: number;
    }
  }
  export interface StreamKey {
    ChannelArn: string;
    Tags?: Tag[];
  }
}
export namespace IdentityStore {
  export interface Group {
    Description?: string;
    DisplayName: string;
    IdentityStoreId: string;
  }
  export interface GroupMembership {
    GroupId: string;
    IdentityStoreId: string;
    MemberId: GroupMembership.MemberId;
  }
  export namespace GroupMembership {
    export interface Attr {
      MembershipId: string;
    }
    export interface MemberId {
      UserId: string;
    }
  }
}
export namespace ImageBuilder {
  export interface Component {
    ChangeDescription?: string;
    Data?: string;
    Description?: string;
    KmsKeyId?: string;
    Name: string;
    Platform: string;
    SupportedOsVersions?: string[];
    Tags?: Record<string, string>;
    Uri?: string;
    Version: string;
  }
  export interface ContainerRecipe {
    Components: ContainerRecipe.ComponentConfiguration[];
    ContainerType: string;
    Description?: string;
    DockerfileTemplateData?: string;
    DockerfileTemplateUri?: string;
    ImageOsVersionOverride?: string;
    InstanceConfiguration?: ContainerRecipe.InstanceConfiguration;
    KmsKeyId?: string;
    Name: string;
    ParentImage: string;
    PlatformOverride?: string;
    Tags?: Record<string, string>;
    TargetRepository: ContainerRecipe.TargetContainerRepository;
    Version: string;
    WorkingDirectory?: string;
  }
  export namespace ContainerRecipe {
    export interface Attr {
      Arn: string;
      Name: string;
    }
    export interface ComponentConfiguration {
      ComponentArn?: string;
      Parameters?: ComponentParameter[];
    }
    export interface ComponentParameter {
      Name: string;
      Value: string[];
    }
    export interface EbsInstanceBlockDeviceSpecification {
      DeleteOnTermination?: boolean;
      Encrypted?: boolean;
      Iops?: number;
      KmsKeyId?: string;
      SnapshotId?: string;
      Throughput?: number;
      VolumeSize?: number;
      VolumeType?: string;
    }
    export interface InstanceBlockDeviceMapping {
      DeviceName?: string;
      Ebs?: EbsInstanceBlockDeviceSpecification;
      NoDevice?: string;
      VirtualName?: string;
    }
    export interface InstanceConfiguration {
      BlockDeviceMappings?: InstanceBlockDeviceMapping[];
      Image?: string;
    }
    export interface TargetContainerRepository {
      RepositoryName?: string;
      Service?: string;
    }
  }
  export interface DistributionConfiguration {
    Description?: string;
    Distributions: DistributionConfiguration.Distribution[];
    Name: string;
    Tags?: Record<string, string>;
  }
  export namespace DistributionConfiguration {
    export interface Attr {
      Arn: string;
      Name: string;
    }
    export interface AmiDistributionConfiguration {
      AmiTags?: Record<string, string>;
      Description?: string;
      KmsKeyId?: string;
      LaunchPermissionConfiguration?: LaunchPermissionConfiguration;
      Name?: string;
      TargetAccountIds?: string[];
    }
    export interface ContainerDistributionConfiguration {
      ContainerTags?: string[];
      Description?: string;
      TargetRepository?: TargetContainerRepository;
    }
    export interface Distribution {
      AmiDistributionConfiguration?: any;
      ContainerDistributionConfiguration?: any;
      FastLaunchConfigurations?: FastLaunchConfiguration[];
      LaunchTemplateConfigurations?: LaunchTemplateConfiguration[];
      LicenseConfigurationArns?: string[];
      Region: string;
    }
    export interface FastLaunchConfiguration {
      AccountId?: string;
      Enabled?: boolean;
      LaunchTemplate?: FastLaunchLaunchTemplateSpecification;
      MaxParallelLaunches?: number;
      SnapshotConfiguration?: FastLaunchSnapshotConfiguration;
    }
    export interface FastLaunchLaunchTemplateSpecification {
      LaunchTemplateId?: string;
      LaunchTemplateName?: string;
      LaunchTemplateVersion?: string;
    }
    export interface FastLaunchSnapshotConfiguration {
      TargetResourceCount?: number;
    }
    export interface LaunchPermissionConfiguration {
      OrganizationArns?: string[];
      OrganizationalUnitArns?: string[];
      UserGroups?: string[];
      UserIds?: string[];
    }
    export interface LaunchTemplateConfiguration {
      AccountId?: string;
      LaunchTemplateId?: string;
      SetDefaultVersion?: boolean;
    }
    export interface TargetContainerRepository {
      RepositoryName?: string;
      Service?: string;
    }
  }
  export interface Image {
    ContainerRecipeArn?: string;
    DistributionConfigurationArn?: string;
    EnhancedImageMetadataEnabled?: boolean;
    ImageRecipeArn?: string;
    ImageTestsConfiguration?: Image.ImageTestsConfiguration;
    InfrastructureConfigurationArn: string;
    Tags?: Record<string, string>;
  }
  export namespace Image {
    export interface Attr {
      Arn: string;
      ImageId: string;
      ImageUri: string;
      Name: string;
    }
    export interface ImageTestsConfiguration {
      ImageTestsEnabled?: boolean;
      TimeoutMinutes?: number;
    }
  }
  export interface ImagePipeline {
    ContainerRecipeArn?: string;
    Description?: string;
    DistributionConfigurationArn?: string;
    EnhancedImageMetadataEnabled?: boolean;
    ImageRecipeArn?: string;
    ImageTestsConfiguration?: ImagePipeline.ImageTestsConfiguration;
    InfrastructureConfigurationArn: string;
    Name: string;
    Schedule?: ImagePipeline.Schedule;
    Status?: string;
    Tags?: Record<string, string>;
  }
  export namespace ImagePipeline {
    export interface Attr {
      Arn: string;
      Name: string;
    }
    export interface ImageTestsConfiguration {
      ImageTestsEnabled?: boolean;
      TimeoutMinutes?: number;
    }
    export interface Schedule {
      PipelineExecutionStartCondition?: string;
      ScheduleExpression?: string;
    }
  }
  export interface ImageRecipe {
    AdditionalInstanceConfiguration?: ImageRecipe.AdditionalInstanceConfiguration;
    BlockDeviceMappings?: ImageRecipe.InstanceBlockDeviceMapping[];
    Components: ImageRecipe.ComponentConfiguration[];
    Description?: string;
    Name: string;
    ParentImage: string;
    Tags?: Record<string, string>;
    Version: string;
    WorkingDirectory?: string;
  }
  export namespace ImageRecipe {
    export interface Attr {
      Arn: string;
      Name: string;
    }
    export interface AdditionalInstanceConfiguration {
      SystemsManagerAgent?: SystemsManagerAgent;
      UserDataOverride?: string;
    }
    export interface ComponentConfiguration {
      ComponentArn?: string;
      Parameters?: ComponentParameter[];
    }
    export interface ComponentParameter {
      Name: string;
      Value: string[];
    }
    export interface EbsInstanceBlockDeviceSpecification {
      DeleteOnTermination?: boolean;
      Encrypted?: boolean;
      Iops?: number;
      KmsKeyId?: string;
      SnapshotId?: string;
      Throughput?: number;
      VolumeSize?: number;
      VolumeType?: string;
    }
    export interface InstanceBlockDeviceMapping {
      DeviceName?: string;
      Ebs?: EbsInstanceBlockDeviceSpecification;
      NoDevice?: string;
      VirtualName?: string;
    }
    export interface SystemsManagerAgent {
      UninstallAfterBuild?: boolean;
    }
  }
  export interface InfrastructureConfiguration {
    Description?: string;
    InstanceMetadataOptions?: InfrastructureConfiguration.InstanceMetadataOptions;
    InstanceProfileName: string;
    InstanceTypes?: string[];
    KeyPair?: string;
    Logging?: InfrastructureConfiguration.Logging;
    Name: string;
    ResourceTags?: Record<string, string>;
    SecurityGroupIds?: string[];
    SnsTopicArn?: string;
    SubnetId?: string;
    Tags?: Record<string, string>;
    TerminateInstanceOnFailure?: boolean;
  }
  export namespace InfrastructureConfiguration {
    export interface Attr {
      Arn: string;
      Name: string;
    }
    export interface InstanceMetadataOptions {
      HttpPutResponseHopLimit?: number;
      HttpTokens?: string;
    }
    export interface Logging {
      S3Logs?: S3Logs;
    }
    export interface S3Logs {
      S3BucketName?: string;
      S3KeyPrefix?: string;
    }
  }
}
export namespace Inspector {
  export interface AssessmentTarget {
    AssessmentTargetName?: string;
    ResourceGroupArn?: string;
  }
  export interface AssessmentTemplate {
    AssessmentTargetArn: string;
    AssessmentTemplateName?: string;
    DurationInSeconds: number;
    RulesPackageArns: string[];
    UserAttributesForFindings?: Tag[];
  }
  export interface ResourceGroup {
    ResourceGroupTags: Tag[];
  }
}
export namespace InspectorV2 {
  export interface Filter {
    Description?: string;
    FilterAction: string;
    FilterCriteria: Filter.FilterCriteria;
    Name: string;
  }
  export namespace Filter {
    export interface Attr {
      Arn: string;
    }
    export interface DateFilter {
      EndInclusive?: number;
      StartInclusive?: number;
    }
    export interface FilterCriteria {
      AwsAccountId?: StringFilter[];
      ComponentId?: StringFilter[];
      ComponentType?: StringFilter[];
      Ec2InstanceImageId?: StringFilter[];
      Ec2InstanceSubnetId?: StringFilter[];
      Ec2InstanceVpcId?: StringFilter[];
      EcrImageArchitecture?: StringFilter[];
      EcrImageHash?: StringFilter[];
      EcrImagePushedAt?: DateFilter[];
      EcrImageRegistry?: StringFilter[];
      EcrImageRepositoryName?: StringFilter[];
      EcrImageTags?: StringFilter[];
      FindingArn?: StringFilter[];
      FindingStatus?: StringFilter[];
      FindingType?: StringFilter[];
      FirstObservedAt?: DateFilter[];
      InspectorScore?: NumberFilter[];
      LastObservedAt?: DateFilter[];
      NetworkProtocol?: StringFilter[];
      PortRange?: PortRangeFilter[];
      RelatedVulnerabilities?: StringFilter[];
      ResourceId?: StringFilter[];
      ResourceTags?: MapFilter[];
      ResourceType?: StringFilter[];
      Severity?: StringFilter[];
      Title?: StringFilter[];
      UpdatedAt?: DateFilter[];
      VendorSeverity?: StringFilter[];
      VulnerabilityId?: StringFilter[];
      VulnerabilitySource?: StringFilter[];
      VulnerablePackages?: PackageFilter[];
    }
    export interface MapFilter {
      Comparison: string;
      Key?: string;
      Value?: string;
    }
    export interface NumberFilter {
      LowerInclusive?: number;
      UpperInclusive?: number;
    }
    export interface PackageFilter {
      Architecture?: StringFilter;
      Epoch?: NumberFilter;
      Name?: StringFilter;
      Release?: StringFilter;
      SourceLayerHash?: StringFilter;
      Version?: StringFilter;
    }
    export interface PortRangeFilter {
      BeginInclusive?: number;
      EndInclusive?: number;
    }
    export interface StringFilter {
      Comparison: string;
      Value: string;
    }
  }
}
export namespace IoT1Click {
  export interface Device {
    DeviceId: string;
    Enabled: boolean;
  }
  export interface Placement {
    AssociatedDevices?: any;
    Attributes?: any;
    PlacementName?: string;
    ProjectName: string;
  }
  export interface Project {
    Description?: string;
    PlacementTemplate: Project.PlacementTemplate;
    ProjectName?: string;
  }
  export namespace Project {
    export interface Attr {
      Arn: string;
      ProjectName: string;
    }
    export interface DeviceTemplate {
      CallbackOverrides?: any;
      DeviceType?: string;
    }
    export interface PlacementTemplate {
      DefaultAttributes?: any;
      DeviceTemplates?: Record<string, DeviceTemplate>;
    }
  }
}
export namespace IoT {
  export interface AccountAuditConfiguration {
    AccountId: string;
    AuditCheckConfigurations: AccountAuditConfiguration.AuditCheckConfigurations;
    AuditNotificationTargetConfigurations?: AccountAuditConfiguration.AuditNotificationTargetConfigurations;
    RoleArn: string;
  }
  export namespace AccountAuditConfiguration {
    export interface Attr {}
    export interface AuditCheckConfiguration {
      Enabled?: boolean;
    }
    export interface AuditCheckConfigurations {
      AuthenticatedCognitoRoleOverlyPermissiveCheck?: AuditCheckConfiguration;
      CaCertificateExpiringCheck?: AuditCheckConfiguration;
      CaCertificateKeyQualityCheck?: AuditCheckConfiguration;
      ConflictingClientIdsCheck?: AuditCheckConfiguration;
      DeviceCertificateExpiringCheck?: AuditCheckConfiguration;
      DeviceCertificateKeyQualityCheck?: AuditCheckConfiguration;
      DeviceCertificateSharedCheck?: AuditCheckConfiguration;
      IntermediateCaRevokedForActiveDeviceCertificatesCheck?: AuditCheckConfiguration;
      IoTPolicyPotentialMisConfigurationCheck?: AuditCheckConfiguration;
      IotPolicyOverlyPermissiveCheck?: AuditCheckConfiguration;
      IotRoleAliasAllowsAccessToUnusedServicesCheck?: AuditCheckConfiguration;
      IotRoleAliasOverlyPermissiveCheck?: AuditCheckConfiguration;
      LoggingDisabledCheck?: AuditCheckConfiguration;
      RevokedCaCertificateStillActiveCheck?: AuditCheckConfiguration;
      RevokedDeviceCertificateStillActiveCheck?: AuditCheckConfiguration;
      UnauthenticatedCognitoRoleOverlyPermissiveCheck?: AuditCheckConfiguration;
    }
    export interface AuditNotificationTarget {
      Enabled?: boolean;
      RoleArn?: string;
      TargetArn?: string;
    }
    export interface AuditNotificationTargetConfigurations {
      Sns?: AuditNotificationTarget;
    }
  }
  export interface Authorizer {
    AuthorizerFunctionArn: string;
    AuthorizerName?: string;
    EnableCachingForHttp?: boolean;
    SigningDisabled?: boolean;
    Status?: string;
    Tags?: Tag[];
    TokenKeyName?: string;
    TokenSigningPublicKeys?: Record<string, string>;
  }
  export interface CACertificate {
    AutoRegistrationStatus?: string;
    CACertificatePem: string;
    CertificateMode?: string;
    RegistrationConfig?: CACertificate.RegistrationConfig;
    RemoveAutoRegistration?: boolean;
    Status: string;
    Tags?: Tag[];
    VerificationCertificatePem?: string;
  }
  export namespace CACertificate {
    export interface Attr {
      Arn: string;
      Id: string;
    }
    export interface RegistrationConfig {
      RoleArn?: string;
      TemplateBody?: string;
      TemplateName?: string;
    }
  }
  export interface Certificate {
    CACertificatePem?: string;
    CertificateMode?: string;
    CertificatePem?: string;
    CertificateSigningRequest?: string;
    Status: string;
  }
  export interface CustomMetric {
    DisplayName?: string;
    MetricName?: string;
    MetricType: string;
    Tags?: Tag[];
  }
  export interface Dimension {
    Name?: string;
    StringValues: string[];
    Tags?: Tag[];
    Type: string;
  }
  export interface DomainConfiguration {
    AuthorizerConfig?: DomainConfiguration.AuthorizerConfig;
    DomainConfigurationName?: string;
    DomainConfigurationStatus?: string;
    DomainName?: string;
    ServerCertificateArns?: string[];
    ServiceType?: string;
    Tags?: Tag[];
    ValidationCertificateArn?: string;
  }
  export namespace DomainConfiguration {
    export interface Attr {
      Arn: string;
      DomainType: string;
      ServerCertificates: ServerCertificateSummary[];
    }
    export interface AuthorizerConfig {
      AllowAuthorizerOverride?: boolean;
      DefaultAuthorizerName?: string;
    }
    export interface ServerCertificateSummary {
      ServerCertificateArn?: string;
      ServerCertificateStatus?: string;
      ServerCertificateStatusDetail?: string;
    }
  }
  export interface FleetMetric {
    AggregationField?: string;
    AggregationType?: FleetMetric.AggregationType;
    Description?: string;
    IndexName?: string;
    MetricName: string;
    Period?: number;
    QueryString?: string;
    QueryVersion?: string;
    Tags?: Tag[];
    Unit?: string;
  }
  export namespace FleetMetric {
    export interface Attr {
      CreationDate: number;
      LastModifiedDate: number;
      MetricArn: string;
      Version: number;
    }
    export interface AggregationType {
      Name: string;
      Values: string[];
    }
  }
  export interface JobTemplate {
    AbortConfig?: any;
    Description: string;
    Document?: string;
    DocumentSource?: string;
    JobArn?: string;
    JobExecutionsRetryConfig?: JobTemplate.JobExecutionsRetryConfig;
    JobExecutionsRolloutConfig?: any;
    JobTemplateId: string;
    PresignedUrlConfig?: any;
    Tags?: Tag[];
    TimeoutConfig?: any;
  }
  export namespace JobTemplate {
    export interface Attr {
      Arn: string;
    }
    export interface AbortConfig {
      CriteriaList: AbortCriteria[];
    }
    export interface AbortCriteria {
      Action: string;
      FailureType: string;
      MinNumberOfExecutedThings: number;
      ThresholdPercentage: number;
    }
    export interface ExponentialRolloutRate {
      BaseRatePerMinute: number;
      IncrementFactor: number;
      RateIncreaseCriteria: RateIncreaseCriteria;
    }
    export interface JobExecutionsRetryConfig {
      RetryCriteriaList?: RetryCriteria[];
    }
    export interface JobExecutionsRolloutConfig {
      ExponentialRolloutRate?: ExponentialRolloutRate;
      MaximumPerMinute?: number;
    }
    export interface PresignedUrlConfig {
      ExpiresInSec?: number;
      RoleArn: string;
    }
    export interface RateIncreaseCriteria {
      NumberOfNotifiedThings?: number;
      NumberOfSucceededThings?: number;
    }
    export interface RetryCriteria {
      FailureType?: string;
      NumberOfRetries?: number;
    }
    export interface TimeoutConfig {
      InProgressTimeoutInMinutes: number;
    }
  }
  export interface Logging {
    AccountId: string;
    DefaultLogLevel: string;
    RoleArn: string;
  }
  export interface MitigationAction {
    ActionName?: string;
    ActionParams: MitigationAction.ActionParams;
    RoleArn: string;
    Tags?: Tag[];
  }
  export namespace MitigationAction {
    export interface Attr {
      MitigationActionArn: string;
      MitigationActionId: string;
    }
    export interface ActionParams {
      AddThingsToThingGroupParams?: AddThingsToThingGroupParams;
      EnableIoTLoggingParams?: EnableIoTLoggingParams;
      PublishFindingToSnsParams?: PublishFindingToSnsParams;
      ReplaceDefaultPolicyVersionParams?: ReplaceDefaultPolicyVersionParams;
      UpdateCACertificateParams?: UpdateCACertificateParams;
      UpdateDeviceCertificateParams?: UpdateDeviceCertificateParams;
    }
    export interface AddThingsToThingGroupParams {
      OverrideDynamicGroups?: boolean;
      ThingGroupNames: string[];
    }
    export interface EnableIoTLoggingParams {
      LogLevel: string;
      RoleArnForLogging: string;
    }
    export interface PublishFindingToSnsParams {
      TopicArn: string;
    }
    export interface ReplaceDefaultPolicyVersionParams {
      TemplateName: string;
    }
    export interface UpdateCACertificateParams {
      Action: string;
    }
    export interface UpdateDeviceCertificateParams {
      Action: string;
    }
  }
  export interface Policy {
    PolicyDocument: any;
    PolicyName?: string;
  }
  export interface PolicyPrincipalAttachment {
    PolicyName: string;
    Principal: string;
  }
  export interface ProvisioningTemplate {
    Description?: string;
    Enabled?: boolean;
    PreProvisioningHook?: ProvisioningTemplate.ProvisioningHook;
    ProvisioningRoleArn: string;
    Tags?: Tag[];
    TemplateBody: string;
    TemplateName?: string;
    TemplateType?: string;
  }
  export namespace ProvisioningTemplate {
    export interface Attr {
      TemplateArn: string;
    }
    export interface ProvisioningHook {
      PayloadVersion?: string;
      TargetArn?: string;
    }
  }
  export interface ResourceSpecificLogging {
    LogLevel: string;
    TargetName: string;
    TargetType: string;
  }
  export interface RoleAlias {
    CredentialDurationSeconds?: number;
    RoleAlias?: string;
    RoleArn: string;
    Tags?: Tag[];
  }
  export interface ScheduledAudit {
    DayOfMonth?: string;
    DayOfWeek?: string;
    Frequency: string;
    ScheduledAuditName?: string;
    Tags?: Tag[];
    TargetCheckNames: string[];
  }
  export interface SecurityProfile {
    AdditionalMetricsToRetainV2?: SecurityProfile.MetricToRetain[];
    AlertTargets?: Record<string, SecurityProfile.AlertTarget>;
    Behaviors?: SecurityProfile.Behavior[];
    SecurityProfileDescription?: string;
    SecurityProfileName?: string;
    Tags?: Tag[];
    TargetArns?: string[];
  }
  export namespace SecurityProfile {
    export interface Attr {
      SecurityProfileArn: string;
    }
    export interface AlertTarget {
      AlertTargetArn: string;
      RoleArn: string;
    }
    export interface Behavior {
      Criteria?: BehaviorCriteria;
      Metric?: string;
      MetricDimension?: MetricDimension;
      Name: string;
      SuppressAlerts?: boolean;
    }
    export interface BehaviorCriteria {
      ComparisonOperator?: string;
      ConsecutiveDatapointsToAlarm?: number;
      ConsecutiveDatapointsToClear?: number;
      DurationSeconds?: number;
      MlDetectionConfig?: MachineLearningDetectionConfig;
      StatisticalThreshold?: StatisticalThreshold;
      Value?: MetricValue;
    }
    export interface MachineLearningDetectionConfig {
      ConfidenceLevel?: string;
    }
    export interface MetricDimension {
      DimensionName: string;
      Operator?: string;
    }
    export interface MetricToRetain {
      Metric: string;
      MetricDimension?: MetricDimension;
    }
    export interface MetricValue {
      Cidrs?: string[];
      Count?: string;
      Number?: number;
      Numbers?: number[];
      Ports?: number[];
      Strings?: string[];
    }
    export interface StatisticalThreshold {
      Statistic?: string;
    }
  }
  export interface Thing {
    AttributePayload?: Thing.AttributePayload;
    ThingName?: string;
  }
  export namespace Thing {
    export interface Attr {
      Arn: string;
      Id: string;
    }
    export interface AttributePayload {
      Attributes?: Record<string, string>;
    }
  }
  export interface ThingPrincipalAttachment {
    Principal: string;
    ThingName: string;
  }
  export interface TopicRule {
    RuleName?: string;
    Tags?: Tag[];
    TopicRulePayload: TopicRule.TopicRulePayload;
  }
  export namespace TopicRule {
    export interface Attr {
      Arn: string;
    }
    export interface Action {
      CloudwatchAlarm?: CloudwatchAlarmAction;
      CloudwatchLogs?: CloudwatchLogsAction;
      CloudwatchMetric?: CloudwatchMetricAction;
      DynamoDB?: DynamoDBAction;
      DynamoDBv2?: DynamoDBv2Action;
      Elasticsearch?: ElasticsearchAction;
      Firehose?: FirehoseAction;
      Http?: HttpAction;
      IotAnalytics?: IotAnalyticsAction;
      IotEvents?: IotEventsAction;
      IotSiteWise?: IotSiteWiseAction;
      Kafka?: KafkaAction;
      Kinesis?: KinesisAction;
      Lambda?: LambdaAction;
      Location?: LocationAction;
      OpenSearch?: OpenSearchAction;
      Republish?: RepublishAction;
      S3?: S3Action;
      Sns?: SnsAction;
      Sqs?: SqsAction;
      StepFunctions?: StepFunctionsAction;
      Timestream?: TimestreamAction;
    }
    export interface AssetPropertyTimestamp {
      OffsetInNanos?: string;
      TimeInSeconds: string;
    }
    export interface AssetPropertyValue {
      Quality?: string;
      Timestamp: AssetPropertyTimestamp;
      Value: AssetPropertyVariant;
    }
    export interface AssetPropertyVariant {
      BooleanValue?: string;
      DoubleValue?: string;
      IntegerValue?: string;
      StringValue?: string;
    }
    export interface CloudwatchAlarmAction {
      AlarmName: string;
      RoleArn: string;
      StateReason: string;
      StateValue: string;
    }
    export interface CloudwatchLogsAction {
      LogGroupName: string;
      RoleArn: string;
    }
    export interface CloudwatchMetricAction {
      MetricName: string;
      MetricNamespace: string;
      MetricTimestamp?: string;
      MetricUnit: string;
      MetricValue: string;
      RoleArn: string;
    }
    export interface DynamoDBAction {
      HashKeyField: string;
      HashKeyType?: string;
      HashKeyValue: string;
      PayloadField?: string;
      RangeKeyField?: string;
      RangeKeyType?: string;
      RangeKeyValue?: string;
      RoleArn: string;
      TableName: string;
    }
    export interface DynamoDBv2Action {
      PutItem?: PutItemInput;
      RoleArn?: string;
    }
    export interface ElasticsearchAction {
      Endpoint: string;
      Id: string;
      Index: string;
      RoleArn: string;
      Type: string;
    }
    export interface FirehoseAction {
      BatchMode?: boolean;
      DeliveryStreamName: string;
      RoleArn: string;
      Separator?: string;
    }
    export interface HttpAction {
      Auth?: HttpAuthorization;
      ConfirmationUrl?: string;
      Headers?: HttpActionHeader[];
      Url: string;
    }
    export interface HttpActionHeader {
      Key: string;
      Value: string;
    }
    export interface HttpAuthorization {
      Sigv4?: SigV4Authorization;
    }
    export interface IotAnalyticsAction {
      BatchMode?: boolean;
      ChannelName: string;
      RoleArn: string;
    }
    export interface IotEventsAction {
      BatchMode?: boolean;
      InputName: string;
      MessageId?: string;
      RoleArn: string;
    }
    export interface IotSiteWiseAction {
      PutAssetPropertyValueEntries: PutAssetPropertyValueEntry[];
      RoleArn: string;
    }
    export interface KafkaAction {
      ClientProperties: Record<string, string>;
      DestinationArn: string;
      Key?: string;
      Partition?: string;
      Topic: string;
    }
    export interface KinesisAction {
      PartitionKey?: string;
      RoleArn: string;
      StreamName: string;
    }
    export interface LambdaAction {
      FunctionArn?: string;
    }
    export interface LocationAction {
      DeviceId: string;
      Latitude: string;
      Longitude: string;
      RoleArn: string;
      Timestamp?: Timestamp;
      TrackerName: string;
    }
    export interface OpenSearchAction {
      Endpoint: string;
      Id: string;
      Index: string;
      RoleArn: string;
      Type: string;
    }
    export interface PutAssetPropertyValueEntry {
      AssetId?: string;
      EntryId?: string;
      PropertyAlias?: string;
      PropertyId?: string;
      PropertyValues: AssetPropertyValue[];
    }
    export interface PutItemInput {
      TableName: string;
    }
    export interface RepublishAction {
      Headers?: RepublishActionHeaders;
      Qos?: number;
      RoleArn: string;
      Topic: string;
    }
    export interface RepublishActionHeaders {
      ContentType?: string;
      CorrelationData?: string;
      MessageExpiry?: string;
      PayloadFormatIndicator?: string;
      ResponseTopic?: string;
      UserProperties?: UserProperty[];
    }
    export interface S3Action {
      BucketName: string;
      CannedAcl?: string;
      Key: string;
      RoleArn: string;
    }
    export interface SigV4Authorization {
      RoleArn: string;
      ServiceName: string;
      SigningRegion: string;
    }
    export interface SnsAction {
      MessageFormat?: string;
      RoleArn: string;
      TargetArn: string;
    }
    export interface SqsAction {
      QueueUrl: string;
      RoleArn: string;
      UseBase64?: boolean;
    }
    export interface StepFunctionsAction {
      ExecutionNamePrefix?: string;
      RoleArn: string;
      StateMachineName: string;
    }
    export interface Timestamp {
      Unit?: string;
      Value: string;
    }
    export interface TimestreamAction {
      DatabaseName: string;
      Dimensions: TimestreamDimension[];
      RoleArn: string;
      TableName: string;
      Timestamp?: TimestreamTimestamp;
    }
    export interface TimestreamDimension {
      Name: string;
      Value: string;
    }
    export interface TimestreamTimestamp {
      Unit: string;
      Value: string;
    }
    export interface TopicRulePayload {
      Actions: Action[];
      AwsIotSqlVersion?: string;
      Description?: string;
      ErrorAction?: Action;
      RuleDisabled?: boolean;
      Sql: string;
    }
    export interface UserProperty {
      Key: string;
      Value: string;
    }
  }
  export interface TopicRuleDestination {
    HttpUrlProperties?: TopicRuleDestination.HttpUrlDestinationSummary;
    Status?: string;
    VpcProperties?: TopicRuleDestination.VpcDestinationProperties;
  }
  export namespace TopicRuleDestination {
    export interface Attr {
      Arn: string;
      StatusReason: string;
    }
    export interface HttpUrlDestinationSummary {
      ConfirmationUrl?: string;
    }
    export interface VpcDestinationProperties {
      RoleArn?: string;
      SecurityGroups?: string[];
      SubnetIds?: string[];
      VpcId?: string;
    }
  }
}
export namespace IoTAnalytics {
  export interface Channel {
    ChannelName?: string;
    ChannelStorage?: Channel.ChannelStorage;
    RetentionPeriod?: Channel.RetentionPeriod;
    Tags?: Tag[];
  }
  export namespace Channel {
    export interface Attr {
      Id: string;
    }
    export interface ChannelStorage {
      CustomerManagedS3?: CustomerManagedS3;
      ServiceManagedS3?: any;
    }
    export interface CustomerManagedS3 {
      Bucket: string;
      KeyPrefix?: string;
      RoleArn: string;
    }
    export interface RetentionPeriod {
      NumberOfDays?: number;
      Unlimited?: boolean;
    }
  }
  export interface Dataset {
    Actions: Dataset.Action[];
    ContentDeliveryRules?: Dataset.DatasetContentDeliveryRule[];
    DatasetName?: string;
    LateDataRules?: Dataset.LateDataRule[];
    RetentionPeriod?: Dataset.RetentionPeriod;
    Tags?: Tag[];
    Triggers?: Dataset.Trigger[];
    VersioningConfiguration?: Dataset.VersioningConfiguration;
  }
  export namespace Dataset {
    export interface Attr {
      Id: string;
    }
    export interface Action {
      ActionName: string;
      ContainerAction?: ContainerAction;
      QueryAction?: QueryAction;
    }
    export interface ContainerAction {
      ExecutionRoleArn: string;
      Image: string;
      ResourceConfiguration: ResourceConfiguration;
      Variables?: Variable[];
    }
    export interface DatasetContentDeliveryRule {
      Destination: DatasetContentDeliveryRuleDestination;
      EntryName?: string;
    }
    export interface DatasetContentDeliveryRuleDestination {
      IotEventsDestinationConfiguration?: IotEventsDestinationConfiguration;
      S3DestinationConfiguration?: S3DestinationConfiguration;
    }
    export interface DatasetContentVersionValue {
      DatasetName: string;
    }
    export interface DeltaTime {
      OffsetSeconds: number;
      TimeExpression: string;
    }
    export interface DeltaTimeSessionWindowConfiguration {
      TimeoutInMinutes: number;
    }
    export interface Filter {
      DeltaTime?: DeltaTime;
    }
    export interface GlueConfiguration {
      DatabaseName: string;
      TableName: string;
    }
    export interface IotEventsDestinationConfiguration {
      InputName: string;
      RoleArn: string;
    }
    export interface LateDataRule {
      RuleConfiguration: LateDataRuleConfiguration;
      RuleName?: string;
    }
    export interface LateDataRuleConfiguration {
      DeltaTimeSessionWindowConfiguration?: DeltaTimeSessionWindowConfiguration;
    }
    export interface OutputFileUriValue {
      FileName: string;
    }
    export interface QueryAction {
      Filters?: Filter[];
      SqlQuery: string;
    }
    export interface ResourceConfiguration {
      ComputeType: string;
      VolumeSizeInGB: number;
    }
    export interface RetentionPeriod {
      NumberOfDays?: number;
      Unlimited?: boolean;
    }
    export interface S3DestinationConfiguration {
      Bucket: string;
      GlueConfiguration?: GlueConfiguration;
      Key: string;
      RoleArn: string;
    }
    export interface Schedule {
      ScheduleExpression: string;
    }
    export interface Trigger {
      Schedule?: Schedule;
      TriggeringDataset?: TriggeringDataset;
    }
    export interface TriggeringDataset {
      DatasetName: string;
    }
    export interface Variable {
      DatasetContentVersionValue?: DatasetContentVersionValue;
      DoubleValue?: number;
      OutputFileUriValue?: OutputFileUriValue;
      StringValue?: string;
      VariableName: string;
    }
    export interface VersioningConfiguration {
      MaxVersions?: number;
      Unlimited?: boolean;
    }
  }
  export interface Datastore {
    DatastoreName?: string;
    DatastorePartitions?: Datastore.DatastorePartitions;
    DatastoreStorage?: Datastore.DatastoreStorage;
    FileFormatConfiguration?: Datastore.FileFormatConfiguration;
    RetentionPeriod?: Datastore.RetentionPeriod;
    Tags?: Tag[];
  }
  export namespace Datastore {
    export interface Attr {
      Id: string;
    }
    export interface Column {
      Name: string;
      Type: string;
    }
    export interface CustomerManagedS3 {
      Bucket: string;
      KeyPrefix?: string;
      RoleArn: string;
    }
    export interface CustomerManagedS3Storage {
      Bucket: string;
      KeyPrefix?: string;
    }
    export interface DatastorePartition {
      Partition?: Partition;
      TimestampPartition?: TimestampPartition;
    }
    export interface DatastorePartitions {
      Partitions?: DatastorePartition[];
    }
    export interface DatastoreStorage {
      CustomerManagedS3?: CustomerManagedS3;
      IotSiteWiseMultiLayerStorage?: IotSiteWiseMultiLayerStorage;
      ServiceManagedS3?: any;
    }
    export interface FileFormatConfiguration {
      JsonConfiguration?: any;
      ParquetConfiguration?: ParquetConfiguration;
    }
    export interface IotSiteWiseMultiLayerStorage {
      CustomerManagedS3Storage?: CustomerManagedS3Storage;
    }
    export interface ParquetConfiguration {
      SchemaDefinition?: SchemaDefinition;
    }
    export interface Partition {
      AttributeName: string;
    }
    export interface RetentionPeriod {
      NumberOfDays?: number;
      Unlimited?: boolean;
    }
    export interface SchemaDefinition {
      Columns?: Column[];
    }
    export interface TimestampPartition {
      AttributeName: string;
      TimestampFormat?: string;
    }
  }
  export interface Pipeline {
    PipelineActivities: Pipeline.Activity[];
    PipelineName?: string;
    Tags?: Tag[];
  }
  export namespace Pipeline {
    export interface Attr {
      Id: string;
    }
    export interface Activity {
      AddAttributes?: AddAttributes;
      Channel?: Channel;
      Datastore?: Datastore;
      DeviceRegistryEnrich?: DeviceRegistryEnrich;
      DeviceShadowEnrich?: DeviceShadowEnrich;
      Filter?: Filter;
      Lambda?: Lambda;
      Math?: Math;
      RemoveAttributes?: RemoveAttributes;
      SelectAttributes?: SelectAttributes;
    }
    export interface AddAttributes {
      Attributes: Record<string, string>;
      Name: string;
      Next?: string;
    }
    export interface Channel {
      ChannelName: string;
      Name: string;
      Next?: string;
    }
    export interface Datastore {
      DatastoreName: string;
      Name: string;
    }
    export interface DeviceRegistryEnrich {
      Attribute: string;
      Name: string;
      Next?: string;
      RoleArn: string;
      ThingName: string;
    }
    export interface DeviceShadowEnrich {
      Attribute: string;
      Name: string;
      Next?: string;
      RoleArn: string;
      ThingName: string;
    }
    export interface Filter {
      Filter: string;
      Name: string;
      Next?: string;
    }
    export interface Lambda {
      BatchSize: number;
      LambdaName: string;
      Name: string;
      Next?: string;
    }
    export interface Math {
      Attribute: string;
      Math: string;
      Name: string;
      Next?: string;
    }
    export interface RemoveAttributes {
      Attributes: string[];
      Name: string;
      Next?: string;
    }
    export interface SelectAttributes {
      Attributes: string[];
      Name: string;
      Next?: string;
    }
  }
}
export namespace IoTCoreDeviceAdvisor {
  export interface SuiteDefinition {
    SuiteDefinitionConfiguration: any;
    Tags?: Tag[];
  }
  export namespace SuiteDefinition {
    export interface Attr {
      SuiteDefinitionArn: string;
      SuiteDefinitionId: string;
      SuiteDefinitionVersion: string;
    }
    export interface DeviceUnderTest {
      CertificateArn?: string;
      ThingArn?: string;
    }
    export interface SuiteDefinitionConfiguration {
      DevicePermissionRoleArn: string;
      Devices?: DeviceUnderTest[];
      IntendedForQualification?: boolean;
      RootGroup: string;
      SuiteDefinitionName?: string;
    }
  }
}
export namespace IoTEvents {
  export interface AlarmModel {
    AlarmCapabilities?: AlarmModel.AlarmCapabilities;
    AlarmEventActions?: AlarmModel.AlarmEventActions;
    AlarmModelDescription?: string;
    AlarmModelName?: string;
    AlarmRule: AlarmModel.AlarmRule;
    Key?: string;
    RoleArn: string;
    Severity?: number;
    Tags?: Tag[];
  }
  export namespace AlarmModel {
    export interface Attr {}
    export interface AcknowledgeFlow {
      Enabled?: boolean;
    }
    export interface AlarmAction {
      DynamoDB?: DynamoDB;
      DynamoDBv2?: DynamoDBv2;
      Firehose?: Firehose;
      IotEvents?: IotEvents;
      IotSiteWise?: IotSiteWise;
      IotTopicPublish?: IotTopicPublish;
      Lambda?: Lambda;
      Sns?: Sns;
      Sqs?: Sqs;
    }
    export interface AlarmCapabilities {
      AcknowledgeFlow?: AcknowledgeFlow;
      InitializationConfiguration?: InitializationConfiguration;
    }
    export interface AlarmEventActions {
      AlarmActions?: AlarmAction[];
    }
    export interface AlarmRule {
      SimpleRule?: SimpleRule;
    }
    export interface AssetPropertyTimestamp {
      OffsetInNanos?: string;
      TimeInSeconds: string;
    }
    export interface AssetPropertyValue {
      Quality?: string;
      Timestamp?: AssetPropertyTimestamp;
      Value: AssetPropertyVariant;
    }
    export interface AssetPropertyVariant {
      BooleanValue?: string;
      DoubleValue?: string;
      IntegerValue?: string;
      StringValue?: string;
    }
    export interface DynamoDB {
      HashKeyField: string;
      HashKeyType?: string;
      HashKeyValue: string;
      Operation?: string;
      Payload?: Payload;
      PayloadField?: string;
      RangeKeyField?: string;
      RangeKeyType?: string;
      RangeKeyValue?: string;
      TableName: string;
    }
    export interface DynamoDBv2 {
      Payload?: Payload;
      TableName: string;
    }
    export interface Firehose {
      DeliveryStreamName: string;
      Payload?: Payload;
      Separator?: string;
    }
    export interface InitializationConfiguration {
      DisabledOnInitialization: boolean;
    }
    export interface IotEvents {
      InputName: string;
      Payload?: Payload;
    }
    export interface IotSiteWise {
      AssetId?: string;
      EntryId?: string;
      PropertyAlias?: string;
      PropertyId?: string;
      PropertyValue?: AssetPropertyValue;
    }
    export interface IotTopicPublish {
      MqttTopic: string;
      Payload?: Payload;
    }
    export interface Lambda {
      FunctionArn: string;
      Payload?: Payload;
    }
    export interface Payload {
      ContentExpression: string;
      Type: string;
    }
    export interface SimpleRule {
      ComparisonOperator: string;
      InputProperty: string;
      Threshold: string;
    }
    export interface Sns {
      Payload?: Payload;
      TargetArn: string;
    }
    export interface Sqs {
      Payload?: Payload;
      QueueUrl: string;
      UseBase64?: boolean;
    }
  }
  export interface DetectorModel {
    DetectorModelDefinition: DetectorModel.DetectorModelDefinition;
    DetectorModelDescription?: string;
    DetectorModelName?: string;
    EvaluationMethod?: string;
    Key?: string;
    RoleArn: string;
    Tags?: Tag[];
  }
  export namespace DetectorModel {
    export interface Attr {}
    export interface Action {
      ClearTimer?: ClearTimer;
      DynamoDB?: DynamoDB;
      DynamoDBv2?: DynamoDBv2;
      Firehose?: Firehose;
      IotEvents?: IotEvents;
      IotSiteWise?: IotSiteWise;
      IotTopicPublish?: IotTopicPublish;
      Lambda?: Lambda;
      ResetTimer?: ResetTimer;
      SetTimer?: SetTimer;
      SetVariable?: SetVariable;
      Sns?: Sns;
      Sqs?: Sqs;
    }
    export interface AssetPropertyTimestamp {
      OffsetInNanos?: string;
      TimeInSeconds: string;
    }
    export interface AssetPropertyValue {
      Quality?: string;
      Timestamp?: AssetPropertyTimestamp;
      Value: AssetPropertyVariant;
    }
    export interface AssetPropertyVariant {
      BooleanValue?: string;
      DoubleValue?: string;
      IntegerValue?: string;
      StringValue?: string;
    }
    export interface ClearTimer {
      TimerName: string;
    }
    export interface DetectorModelDefinition {
      InitialStateName: string;
      States: State[];
    }
    export interface DynamoDB {
      HashKeyField: string;
      HashKeyType?: string;
      HashKeyValue: string;
      Operation?: string;
      Payload?: Payload;
      PayloadField?: string;
      RangeKeyField?: string;
      RangeKeyType?: string;
      RangeKeyValue?: string;
      TableName: string;
    }
    export interface DynamoDBv2 {
      Payload?: Payload;
      TableName: string;
    }
    export interface Event {
      Actions?: Action[];
      Condition?: string;
      EventName: string;
    }
    export interface Firehose {
      DeliveryStreamName: string;
      Payload?: Payload;
      Separator?: string;
    }
    export interface IotEvents {
      InputName: string;
      Payload?: Payload;
    }
    export interface IotSiteWise {
      AssetId?: string;
      EntryId?: string;
      PropertyAlias?: string;
      PropertyId?: string;
      PropertyValue: AssetPropertyValue;
    }
    export interface IotTopicPublish {
      MqttTopic: string;
      Payload?: Payload;
    }
    export interface Lambda {
      FunctionArn: string;
      Payload?: Payload;
    }
    export interface OnEnter {
      Events?: Event[];
    }
    export interface OnExit {
      Events?: Event[];
    }
    export interface OnInput {
      Events?: Event[];
      TransitionEvents?: TransitionEvent[];
    }
    export interface Payload {
      ContentExpression: string;
      Type: string;
    }
    export interface ResetTimer {
      TimerName: string;
    }
    export interface SetTimer {
      DurationExpression?: string;
      Seconds?: number;
      TimerName: string;
    }
    export interface SetVariable {
      Value: string;
      VariableName: string;
    }
    export interface Sns {
      Payload?: Payload;
      TargetArn: string;
    }
    export interface Sqs {
      Payload?: Payload;
      QueueUrl: string;
      UseBase64?: boolean;
    }
    export interface State {
      OnEnter?: OnEnter;
      OnExit?: OnExit;
      OnInput?: OnInput;
      StateName: string;
    }
    export interface TransitionEvent {
      Actions?: Action[];
      Condition: string;
      EventName: string;
      NextState: string;
    }
  }
  export interface Input {
    InputDefinition: Input.InputDefinition;
    InputDescription?: string;
    InputName?: string;
    Tags?: Tag[];
  }
  export namespace Input {
    export interface Attr {}
    export interface Attribute {
      JsonPath: string;
    }
    export interface InputDefinition {
      Attributes: Attribute[];
    }
  }
}
export namespace IoTFleetHub {
  export interface Application {
    ApplicationDescription?: string;
    ApplicationName: string;
    RoleArn: string;
    Tags?: Tag[];
  }
}
export namespace IoTFleetWise {
  export interface Campaign {
    Action: string;
    CollectionScheme: Campaign.CollectionScheme;
    Compression?: string;
    DataExtraDimensions?: string[];
    Description?: string;
    DiagnosticsMode?: string;
    ExpiryTime?: string;
    Name: string;
    PostTriggerCollectionDuration?: number;
    Priority?: number;
    SignalCatalogArn: string;
    SignalsToCollect?: Campaign.SignalInformation[];
    SpoolingMode?: string;
    StartTime?: string;
    Tags?: Tag[];
    TargetArn: string;
  }
  export namespace Campaign {
    export interface Attr {
      Arn: string;
      CreationTime: string;
      LastModificationTime: string;
      Status: string;
    }
    export interface CollectionScheme {
      ConditionBasedCollectionScheme?: ConditionBasedCollectionScheme;
      TimeBasedCollectionScheme?: TimeBasedCollectionScheme;
    }
    export interface ConditionBasedCollectionScheme {
      ConditionLanguageVersion?: number;
      Expression: string;
      MinimumTriggerIntervalMs?: number;
      TriggerMode?: string;
    }
    export interface SignalInformation {
      MaxSampleCount?: number;
      MinimumSamplingIntervalMs?: number;
      Name: string;
    }
    export interface TimeBasedCollectionScheme {
      PeriodMs: number;
    }
  }
  export interface DecoderManifest {
    Description?: string;
    ModelManifestArn: string;
    Name: string;
    NetworkInterfaces?: DecoderManifest.NetworkInterfacesItems[];
    SignalDecoders?: DecoderManifest.SignalDecodersItems[];
    Status?: string;
    Tags?: Tag[];
  }
  export namespace DecoderManifest {
    export interface Attr {
      Arn: string;
      CreationTime: string;
      LastModificationTime: string;
    }
    export interface CanInterface {
      Name: string;
      ProtocolName?: string;
      ProtocolVersion?: string;
    }
    export interface CanSignal {
      Factor: string;
      IsBigEndian: string;
      IsSigned: string;
      Length: string;
      MessageId: string;
      Name?: string;
      Offset: string;
      StartBit: string;
    }
    export interface NetworkInterfacesItems {
      CanInterface?: CanInterface;
      InterfaceId: string;
      ObdInterface?: ObdInterface;
      Type: string;
    }
    export interface ObdInterface {
      DtcRequestIntervalSeconds?: string;
      HasTransmissionEcu?: string;
      Name: string;
      ObdStandard?: string;
      PidRequestIntervalSeconds?: string;
      RequestMessageId: string;
      UseExtendedIds?: string;
    }
    export interface ObdSignal {
      BitMaskLength?: string;
      BitRightShift?: string;
      ByteLength: string;
      Offset: string;
      Pid: string;
      PidResponseLength: string;
      Scaling: string;
      ServiceMode: string;
      StartByte: string;
    }
    export interface SignalDecodersItems {
      CanSignal?: CanSignal;
      FullyQualifiedName: string;
      InterfaceId: string;
      ObdSignal?: ObdSignal;
      Type: string;
    }
  }
  export interface Fleet {
    Description?: string;
    Id: string;
    SignalCatalogArn: string;
    Tags?: Tag[];
  }
  export interface ModelManifest {
    Description?: string;
    Name: string;
    Nodes?: string[];
    SignalCatalogArn: string;
    Status?: string;
    Tags?: Tag[];
  }
  export interface SignalCatalog {
    Description?: string;
    Name?: string;
    NodeCounts?: SignalCatalog.NodeCounts;
    Nodes?: SignalCatalog.Node[];
    Tags?: Tag[];
  }
  export namespace SignalCatalog {
    export interface Attr {
      Arn: string;
      CreationTime: string;
      LastModificationTime: string;
      "NodeCounts.TotalActuators": number;
      "NodeCounts.TotalAttributes": number;
      "NodeCounts.TotalBranches": number;
      "NodeCounts.TotalNodes": number;
      "NodeCounts.TotalSensors": number;
    }
    export interface Actuator {
      AllowedValues?: string[];
      AssignedValue?: string;
      DataType: string;
      Description?: string;
      FullyQualifiedName: string;
      Max?: number;
      Min?: number;
      Unit?: string;
    }
    export interface Attribute {
      AllowedValues?: string[];
      AssignedValue?: string;
      DataType: string;
      DefaultValue?: string;
      Description?: string;
      FullyQualifiedName: string;
      Max?: number;
      Min?: number;
      Unit?: string;
    }
    export interface Branch {
      Description?: string;
      FullyQualifiedName: string;
    }
    export interface Node {
      Actuator?: Actuator;
      Attribute?: Attribute;
      Branch?: Branch;
      Sensor?: Sensor;
    }
    export interface NodeCounts {
      TotalActuators?: number;
      TotalAttributes?: number;
      TotalBranches?: number;
      TotalNodes?: number;
      TotalSensors?: number;
    }
    export interface Sensor {
      AllowedValues?: string[];
      DataType: string;
      Description?: string;
      FullyQualifiedName: string;
      Max?: number;
      Min?: number;
      Unit?: string;
    }
  }
  export interface Vehicle {
    AssociationBehavior?: string;
    Attributes?: Record<string, string>;
    DecoderManifestArn: string;
    ModelManifestArn: string;
    Name: string;
    Tags?: Tag[];
  }
}
export namespace IoTSiteWise {
  export interface AccessPolicy {
    AccessPolicyIdentity: AccessPolicy.AccessPolicyIdentity;
    AccessPolicyPermission: string;
    AccessPolicyResource: AccessPolicy.AccessPolicyResource;
  }
  export namespace AccessPolicy {
    export interface Attr {
      AccessPolicyArn: string;
      AccessPolicyId: string;
    }
    export interface AccessPolicyIdentity {
      IamRole?: IamRole;
      IamUser?: IamUser;
      User?: User;
    }
    export interface AccessPolicyResource {
      Portal?: Portal;
      Project?: Project;
    }
    export interface IamRole {
      arn?: string;
    }
    export interface IamUser {
      arn?: string;
    }
    export interface Portal {
      id?: string;
    }
    export interface Project {
      id?: string;
    }
    export interface User {
      id?: string;
    }
  }
  export interface Asset {
    AssetDescription?: string;
    AssetHierarchies?: Asset.AssetHierarchy[];
    AssetModelId: string;
    AssetName: string;
    AssetProperties?: Asset.AssetProperty[];
    Tags?: Tag[];
  }
  export namespace Asset {
    export interface Attr {
      AssetArn: string;
      AssetId: string;
    }
    export interface AssetHierarchy {
      ChildAssetId: string;
      LogicalId: string;
    }
    export interface AssetProperty {
      Alias?: string;
      LogicalId: string;
      NotificationState?: string;
      Unit?: string;
    }
  }
  export interface AssetModel {
    AssetModelCompositeModels?: AssetModel.AssetModelCompositeModel[];
    AssetModelDescription?: string;
    AssetModelHierarchies?: AssetModel.AssetModelHierarchy[];
    AssetModelName: string;
    AssetModelProperties?: AssetModel.AssetModelProperty[];
    Tags?: Tag[];
  }
  export namespace AssetModel {
    export interface Attr {
      AssetModelArn: string;
      AssetModelId: string;
    }
    export interface AssetModelCompositeModel {
      CompositeModelProperties?: AssetModelProperty[];
      Description?: string;
      Name: string;
      Type: string;
    }
    export interface AssetModelHierarchy {
      ChildAssetModelId: string;
      LogicalId: string;
      Name: string;
    }
    export interface AssetModelProperty {
      DataType: string;
      DataTypeSpec?: string;
      LogicalId: string;
      Name: string;
      Type: PropertyType;
      Unit?: string;
    }
    export interface Attribute {
      DefaultValue?: string;
    }
    export interface ExpressionVariable {
      Name: string;
      Value: VariableValue;
    }
    export interface Metric {
      Expression: string;
      Variables: ExpressionVariable[];
      Window: MetricWindow;
    }
    export interface MetricWindow {
      Tumbling?: TumblingWindow;
    }
    export interface PropertyType {
      Attribute?: Attribute;
      Metric?: Metric;
      Transform?: Transform;
      TypeName: string;
    }
    export interface Transform {
      Expression: string;
      Variables: ExpressionVariable[];
    }
    export interface TumblingWindow {
      Interval: string;
      Offset?: string;
    }
    export interface VariableValue {
      HierarchyLogicalId?: string;
      PropertyLogicalId: string;
    }
  }
  export interface Dashboard {
    DashboardDefinition: string;
    DashboardDescription: string;
    DashboardName: string;
    ProjectId?: string;
    Tags?: Tag[];
  }
  export interface Gateway {
    GatewayCapabilitySummaries?: Gateway.GatewayCapabilitySummary[];
    GatewayName: string;
    GatewayPlatform: Gateway.GatewayPlatform;
    Tags?: Tag[];
  }
  export namespace Gateway {
    export interface Attr {
      GatewayId: string;
    }
    export interface GatewayCapabilitySummary {
      CapabilityConfiguration?: string;
      CapabilityNamespace: string;
    }
    export interface GatewayPlatform {
      Greengrass?: Greengrass;
      GreengrassV2?: GreengrassV2;
    }
    export interface Greengrass {
      GroupArn: string;
    }
    export interface GreengrassV2 {
      CoreDeviceThingName: string;
    }
  }
  export interface Portal {
    Alarms?: any;
    NotificationSenderEmail?: string;
    PortalAuthMode?: string;
    PortalContactEmail: string;
    PortalDescription?: string;
    PortalName: string;
    RoleArn: string;
    Tags?: Tag[];
  }
  export namespace Portal {
    export interface Attr {
      PortalArn: string;
      PortalClientId: string;
      PortalId: string;
      PortalStartUrl: string;
    }
    export interface Alarms {
      AlarmRoleArn?: string;
      NotificationLambdaArn?: string;
    }
  }
  export interface Project {
    AssetIds?: string[];
    PortalId: string;
    ProjectDescription?: string;
    ProjectName: string;
    Tags?: Tag[];
  }
}
export namespace IoTThingsGraph {
  export interface FlowTemplate {
    CompatibleNamespaceVersion?: number;
    Definition: FlowTemplate.DefinitionDocument;
  }
  export namespace FlowTemplate {
    export interface Attr {}
    export interface DefinitionDocument {
      Language: string;
      Text: string;
    }
  }
}
export namespace IoTTwinMaker {
  export interface ComponentType {
    ComponentTypeId: string;
    Description?: string;
    ExtendsFrom?: string[];
    Functions?: Record<string, ComponentType.Function>;
    IsSingleton?: boolean;
    PropertyDefinitions?: Record<string, ComponentType.PropertyDefinition>;
    PropertyGroups?: Record<string, ComponentType.PropertyGroup>;
    Tags?: Record<string, string>;
    WorkspaceId: string;
  }
  export namespace ComponentType {
    export interface Attr {
      Arn: string;
      CreationDateTime: string;
      IsAbstract: boolean;
      IsSchemaInitialized: boolean;
      "Status.Error.Code": string;
      "Status.Error.Message": string;
      "Status.State": string;
      UpdateDateTime: string;
    }
    export interface DataConnector {
      IsNative?: boolean;
      Lambda?: LambdaFunction;
    }
    export interface DataType {
      AllowedValues?: DataValue[];
      NestedType?: DataType;
      Relationship?: Relationship;
      Type: string;
      UnitOfMeasure?: string;
    }
    export interface DataValue {
      BooleanValue?: boolean;
      DoubleValue?: number;
      Expression?: string;
      IntegerValue?: number;
      ListValue?: DataValue[];
      LongValue?: number;
      MapValue?: Record<string, DataValue>;
      RelationshipValue?: any;
      StringValue?: string;
    }
    export interface Error {
      Code?: string;
      Message?: string;
    }
    export interface Function {
      ImplementedBy?: DataConnector;
      RequiredProperties?: string[];
      Scope?: string;
    }
    export interface LambdaFunction {
      Arn: string;
    }
    export interface PropertyDefinition {
      Configurations?: Record<string, string>;
      DataType?: DataType;
      DefaultValue?: DataValue;
      IsExternalId?: boolean;
      IsRequiredInEntity?: boolean;
      IsStoredExternally?: boolean;
      IsTimeSeries?: boolean;
    }
    export interface PropertyGroup {
      GroupType?: string;
      PropertyNames?: string[];
    }
    export interface Relationship {
      RelationshipType?: string;
      TargetComponentTypeId?: string;
    }
    export interface RelationshipValue {
      TargetComponentName?: string;
      TargetEntityId?: string;
    }
    export interface Status {
      Error?: Error;
      State?: string;
    }
  }
  export interface Entity {
    Components?: Record<string, Entity.Component>;
    Description?: string;
    EntityId?: string;
    EntityName: string;
    ParentEntityId?: string;
    Tags?: Record<string, string>;
    WorkspaceId: string;
  }
  export namespace Entity {
    export interface Attr {
      Arn: string;
      CreationDateTime: string;
      HasChildEntities: boolean;
      "Status.Error.Code": string;
      "Status.Error.Message": string;
      "Status.State": string;
      UpdateDateTime: string;
    }
    export interface Component {
      ComponentName?: string;
      ComponentTypeId?: string;
      DefinedIn?: string;
      Description?: string;
      Properties?: Record<string, Property>;
      PropertyGroups?: Record<string, PropertyGroup>;
      Status?: Status;
    }
    export interface DataType {
      AllowedValues?: DataValue[];
      NestedType?: DataType;
      Relationship?: Relationship;
      Type?: string;
      UnitOfMeasure?: string;
    }
    export interface DataValue {
      BooleanValue?: boolean;
      DoubleValue?: number;
      Expression?: string;
      IntegerValue?: number;
      ListValue?: DataValue[];
      LongValue?: number;
      MapValue?: Record<string, DataValue>;
      RelationshipValue?: any;
      StringValue?: string;
    }
    export interface Definition {
      Configuration?: Record<string, string>;
      DataType?: DataType;
      DefaultValue?: DataValue;
      IsExternalId?: boolean;
      IsFinal?: boolean;
      IsImported?: boolean;
      IsInherited?: boolean;
      IsRequiredInEntity?: boolean;
      IsStoredExternally?: boolean;
      IsTimeSeries?: boolean;
    }
    export interface Error {
      Code?: string;
      Message?: string;
    }
    export interface Property {
      Definition?: any;
      Value?: DataValue;
    }
    export interface PropertyGroup {
      GroupType?: string;
      PropertyNames?: string[];
    }
    export interface Relationship {
      RelationshipType?: string;
      TargetComponentTypeId?: string;
    }
    export interface RelationshipValue {
      TargetComponentName?: string;
      TargetEntityId?: string;
    }
    export interface Status {
      Error?: any;
      State?: string;
    }
  }
  export interface Scene {
    Capabilities?: string[];
    ContentLocation: string;
    Description?: string;
    SceneId: string;
    Tags?: Record<string, string>;
    WorkspaceId: string;
  }
  export interface SyncJob {
    SyncRole: string;
    SyncSource: string;
    Tags?: Record<string, string>;
    WorkspaceId: string;
  }
  export interface Workspace {
    Description?: string;
    Role: string;
    S3Location: string;
    Tags?: Record<string, string>;
    WorkspaceId: string;
  }
}
export namespace IoTWireless {
  export interface Destination {
    Description?: string;
    Expression: string;
    ExpressionType: string;
    Name: string;
    RoleArn: string;
    Tags?: Tag[];
  }
  export interface DeviceProfile {
    LoRaWAN?: DeviceProfile.LoRaWANDeviceProfile;
    Name?: string;
    Tags?: Tag[];
  }
  export namespace DeviceProfile {
    export interface Attr {
      Arn: string;
      Id: string;
    }
    export interface LoRaWANDeviceProfile {
      ClassBTimeout?: number;
      ClassCTimeout?: number;
      FactoryPresetFreqsList?: number[];
      MacVersion?: string;
      MaxDutyCycle?: number;
      MaxEirp?: number;
      PingSlotDr?: number;
      PingSlotFreq?: number;
      PingSlotPeriod?: number;
      RegParamsRevision?: string;
      RfRegion?: string;
      RxDataRate2?: number;
      RxDelay1?: number;
      RxDrOffset1?: number;
      RxFreq2?: number;
      Supports32BitFCnt?: boolean;
      SupportsClassB?: boolean;
      SupportsClassC?: boolean;
      SupportsJoin?: boolean;
    }
  }
  export interface FuotaTask {
    AssociateMulticastGroup?: string;
    AssociateWirelessDevice?: string;
    Description?: string;
    DisassociateMulticastGroup?: string;
    DisassociateWirelessDevice?: string;
    FirmwareUpdateImage: string;
    FirmwareUpdateRole: string;
    LoRaWAN: FuotaTask.LoRaWAN;
    Name?: string;
    Tags?: Tag[];
  }
  export namespace FuotaTask {
    export interface Attr {
      Arn: string;
      FuotaTaskStatus: string;
      Id: string;
      "LoRaWAN.StartTime": string;
    }
    export interface LoRaWAN {
      RfRegion: string;
      StartTime?: string;
    }
  }
  export interface MulticastGroup {
    AssociateWirelessDevice?: string;
    Description?: string;
    DisassociateWirelessDevice?: string;
    LoRaWAN: MulticastGroup.LoRaWAN;
    Name?: string;
    Tags?: Tag[];
  }
  export namespace MulticastGroup {
    export interface Attr {
      Arn: string;
      Id: string;
      "LoRaWAN.NumberOfDevicesInGroup": number;
      "LoRaWAN.NumberOfDevicesRequested": number;
      Status: string;
    }
    export interface LoRaWAN {
      DlClass: string;
      NumberOfDevicesInGroup?: number;
      NumberOfDevicesRequested?: number;
      RfRegion: string;
    }
  }
  export interface NetworkAnalyzerConfiguration {
    Description?: string;
    Name: string;
    Tags?: Tag[];
    TraceContent?: any;
    WirelessDevices?: string[];
    WirelessGateways?: string[];
  }
  export namespace NetworkAnalyzerConfiguration {
    export interface Attr {
      Arn: string;
    }
    export interface TraceContent {
      LogLevel?: string;
      WirelessDeviceFrameInfo?: string;
    }
  }
  export interface PartnerAccount {
    AccountLinked?: boolean;
    PartnerAccountId?: string;
    PartnerType?: string;
    Sidewalk?: PartnerAccount.SidewalkAccountInfo;
    SidewalkResponse?: PartnerAccount.SidewalkAccountInfoWithFingerprint;
    SidewalkUpdate?: PartnerAccount.SidewalkUpdateAccount;
    Tags?: Tag[];
  }
  export namespace PartnerAccount {
    export interface Attr {
      Arn: string;
      Fingerprint: string;
    }
    export interface SidewalkAccountInfo {
      AppServerPrivateKey: string;
    }
    export interface SidewalkAccountInfoWithFingerprint {
      AmazonId?: string;
      Arn?: string;
      Fingerprint?: string;
    }
    export interface SidewalkUpdateAccount {
      AppServerPrivateKey?: string;
    }
  }
  export interface ServiceProfile {
    LoRaWAN?: ServiceProfile.LoRaWANServiceProfile;
    Name?: string;
    Tags?: Tag[];
  }
  export namespace ServiceProfile {
    export interface Attr {
      Arn: string;
      Id: string;
      "LoRaWAN.ChannelMask": string;
      "LoRaWAN.DevStatusReqFreq": number;
      "LoRaWAN.DlBucketSize": number;
      "LoRaWAN.DlRate": number;
      "LoRaWAN.DlRatePolicy": string;
      "LoRaWAN.DrMax": number;
      "LoRaWAN.DrMin": number;
      "LoRaWAN.HrAllowed": boolean;
      "LoRaWAN.MinGwDiversity": number;
      "LoRaWAN.NwkGeoLoc": boolean;
      "LoRaWAN.PrAllowed": boolean;
      "LoRaWAN.RaAllowed": boolean;
      "LoRaWAN.ReportDevStatusBattery": boolean;
      "LoRaWAN.ReportDevStatusMargin": boolean;
      "LoRaWAN.TargetPer": number;
      "LoRaWAN.UlBucketSize": number;
      "LoRaWAN.UlRate": number;
      "LoRaWAN.UlRatePolicy": string;
      LoRaWANResponse: Record<string, string>;
    }
    export interface LoRaWANServiceProfile {
      AddGwMetadata?: boolean;
      ChannelMask?: string;
      DevStatusReqFreq?: number;
      DlBucketSize?: number;
      DlRate?: number;
      DlRatePolicy?: string;
      DrMax?: number;
      DrMin?: number;
      HrAllowed?: boolean;
      MinGwDiversity?: number;
      NwkGeoLoc?: boolean;
      PrAllowed?: boolean;
      RaAllowed?: boolean;
      ReportDevStatusBattery?: boolean;
      ReportDevStatusMargin?: boolean;
      TargetPer?: number;
      UlBucketSize?: number;
      UlRate?: number;
      UlRatePolicy?: string;
    }
  }
  export interface TaskDefinition {
    AutoCreateTasks: boolean;
    LoRaWANUpdateGatewayTaskEntry?: TaskDefinition.LoRaWANUpdateGatewayTaskEntry;
    Name?: string;
    Tags?: Tag[];
    TaskDefinitionType?: string;
    Update?: TaskDefinition.UpdateWirelessGatewayTaskCreate;
  }
  export namespace TaskDefinition {
    export interface Attr {
      Arn: string;
      Id: string;
    }
    export interface LoRaWANGatewayVersion {
      Model?: string;
      PackageVersion?: string;
      Station?: string;
    }
    export interface LoRaWANUpdateGatewayTaskCreate {
      CurrentVersion?: LoRaWANGatewayVersion;
      SigKeyCrc?: number;
      UpdateSignature?: string;
      UpdateVersion?: LoRaWANGatewayVersion;
    }
    export interface LoRaWANUpdateGatewayTaskEntry {
      CurrentVersion?: LoRaWANGatewayVersion;
      UpdateVersion?: LoRaWANGatewayVersion;
    }
    export interface UpdateWirelessGatewayTaskCreate {
      LoRaWAN?: LoRaWANUpdateGatewayTaskCreate;
      UpdateDataRole?: string;
      UpdateDataSource?: string;
    }
  }
  export interface WirelessDevice {
    Description?: string;
    DestinationName: string;
    LastUplinkReceivedAt?: string;
    LoRaWAN?: WirelessDevice.LoRaWANDevice;
    Name?: string;
    Tags?: Tag[];
    ThingArn?: string;
    Type: string;
  }
  export namespace WirelessDevice {
    export interface Attr {
      Arn: string;
      Id: string;
      ThingName: string;
    }
    export interface AbpV10x {
      DevAddr: string;
      SessionKeys: SessionKeysAbpV10x;
    }
    export interface AbpV11 {
      DevAddr: string;
      SessionKeys: SessionKeysAbpV11;
    }
    export interface LoRaWANDevice {
      AbpV10x?: AbpV10x;
      AbpV11?: AbpV11;
      DevEui?: string;
      DeviceProfileId?: string;
      OtaaV10x?: OtaaV10x;
      OtaaV11?: OtaaV11;
      ServiceProfileId?: string;
    }
    export interface OtaaV10x {
      AppEui: string;
      AppKey: string;
    }
    export interface OtaaV11 {
      AppKey: string;
      JoinEui: string;
      NwkKey: string;
    }
    export interface SessionKeysAbpV10x {
      AppSKey: string;
      NwkSKey: string;
    }
    export interface SessionKeysAbpV11 {
      AppSKey: string;
      FNwkSIntKey: string;
      NwkSEncKey: string;
      SNwkSIntKey: string;
    }
  }
  export interface WirelessGateway {
    Description?: string;
    LastUplinkReceivedAt?: string;
    LoRaWAN: WirelessGateway.LoRaWANGateway;
    Name?: string;
    Tags?: Tag[];
    ThingArn?: string;
    ThingName?: string;
  }
  export namespace WirelessGateway {
    export interface Attr {
      Arn: string;
      Id: string;
    }
    export interface LoRaWANGateway {
      GatewayEui: string;
      RfRegion: string;
    }
  }
}
export namespace KMS {
  export interface Alias {
    AliasName: string;
    TargetKeyId: string;
  }
  export interface Key {
    Description?: string;
    EnableKeyRotation?: boolean;
    Enabled?: boolean;
    KeyPolicy: any;
    KeySpec?: string;
    KeyUsage?: string;
    MultiRegion?: boolean;
    PendingWindowInDays?: number;
    Tags?: Tag[];
  }
  export interface ReplicaKey {
    Description?: string;
    Enabled?: boolean;
    KeyPolicy: any;
    PendingWindowInDays?: number;
    PrimaryKeyArn: string;
    Tags?: Tag[];
  }
}
export namespace KafkaConnect {
  export interface Connector {
    Capacity: Connector.Capacity;
    ConnectorConfiguration: Record<string, string>;
    ConnectorDescription?: string;
    ConnectorName: string;
    KafkaCluster: Connector.KafkaCluster;
    KafkaClusterClientAuthentication: Connector.KafkaClusterClientAuthentication;
    KafkaClusterEncryptionInTransit: Connector.KafkaClusterEncryptionInTransit;
    KafkaConnectVersion: string;
    LogDelivery?: Connector.LogDelivery;
    Plugins: Connector.Plugin[];
    ServiceExecutionRoleArn: string;
    WorkerConfiguration?: Connector.WorkerConfiguration;
  }
  export namespace Connector {
    export interface Attr {
      ConnectorArn: string;
    }
    export interface ApacheKafkaCluster {
      BootstrapServers: string;
      Vpc: Vpc;
    }
    export interface AutoScaling {
      MaxWorkerCount: number;
      McuCount: number;
      MinWorkerCount: number;
      ScaleInPolicy: ScaleInPolicy;
      ScaleOutPolicy: ScaleOutPolicy;
    }
    export interface Capacity {
      AutoScaling?: AutoScaling;
      ProvisionedCapacity?: ProvisionedCapacity;
    }
    export interface CloudWatchLogsLogDelivery {
      Enabled: boolean;
      LogGroup?: string;
    }
    export interface CustomPlugin {
      CustomPluginArn: string;
      Revision: number;
    }
    export interface FirehoseLogDelivery {
      DeliveryStream?: string;
      Enabled: boolean;
    }
    export interface KafkaCluster {
      ApacheKafkaCluster: ApacheKafkaCluster;
    }
    export interface KafkaClusterClientAuthentication {
      AuthenticationType: string;
    }
    export interface KafkaClusterEncryptionInTransit {
      EncryptionType: string;
    }
    export interface LogDelivery {
      WorkerLogDelivery: WorkerLogDelivery;
    }
    export interface Plugin {
      CustomPlugin: CustomPlugin;
    }
    export interface ProvisionedCapacity {
      McuCount?: number;
      WorkerCount: number;
    }
    export interface S3LogDelivery {
      Bucket?: string;
      Enabled: boolean;
      Prefix?: string;
    }
    export interface ScaleInPolicy {
      CpuUtilizationPercentage: number;
    }
    export interface ScaleOutPolicy {
      CpuUtilizationPercentage: number;
    }
    export interface Vpc {
      SecurityGroups: string[];
      Subnets: string[];
    }
    export interface WorkerConfiguration {
      Revision: number;
      WorkerConfigurationArn: string;
    }
    export interface WorkerLogDelivery {
      CloudWatchLogs?: CloudWatchLogsLogDelivery;
      Firehose?: FirehoseLogDelivery;
      S3?: S3LogDelivery;
    }
  }
}
export namespace Kendra {
  export interface DataSource {
    CustomDocumentEnrichmentConfiguration?: DataSource.CustomDocumentEnrichmentConfiguration;
    DataSourceConfiguration?: DataSource.DataSourceConfiguration;
    Description?: string;
    IndexId: string;
    Name: string;
    RoleArn?: string;
    Schedule?: string;
    Tags?: Tag[];
    Type: string;
  }
  export namespace DataSource {
    export interface Attr {
      Arn: string;
      Id: string;
    }
    export interface AccessControlListConfiguration {
      KeyPath?: string;
    }
    export interface AclConfiguration {
      AllowedGroupsColumnName: string;
    }
    export interface ColumnConfiguration {
      ChangeDetectingColumns: string[];
      DocumentDataColumnName: string;
      DocumentIdColumnName: string;
      DocumentTitleColumnName?: string;
      FieldMappings?: DataSourceToIndexFieldMapping[];
    }
    export interface ConfluenceAttachmentConfiguration {
      AttachmentFieldMappings?: ConfluenceAttachmentToIndexFieldMapping[];
      CrawlAttachments?: boolean;
    }
    export interface ConfluenceAttachmentToIndexFieldMapping {
      DataSourceFieldName: string;
      DateFieldFormat?: string;
      IndexFieldName: string;
    }
    export interface ConfluenceBlogConfiguration {
      BlogFieldMappings?: ConfluenceBlogToIndexFieldMapping[];
    }
    export interface ConfluenceBlogToIndexFieldMapping {
      DataSourceFieldName: string;
      DateFieldFormat?: string;
      IndexFieldName: string;
    }
    export interface ConfluenceConfiguration {
      AttachmentConfiguration?: ConfluenceAttachmentConfiguration;
      BlogConfiguration?: ConfluenceBlogConfiguration;
      ExclusionPatterns?: string[];
      InclusionPatterns?: string[];
      PageConfiguration?: ConfluencePageConfiguration;
      SecretArn: string;
      ServerUrl: string;
      SpaceConfiguration?: ConfluenceSpaceConfiguration;
      Version: string;
      VpcConfiguration?: DataSourceVpcConfiguration;
    }
    export interface ConfluencePageConfiguration {
      PageFieldMappings?: ConfluencePageToIndexFieldMapping[];
    }
    export interface ConfluencePageToIndexFieldMapping {
      DataSourceFieldName: string;
      DateFieldFormat?: string;
      IndexFieldName: string;
    }
    export interface ConfluenceSpaceConfiguration {
      CrawlArchivedSpaces?: boolean;
      CrawlPersonalSpaces?: boolean;
      ExcludeSpaces?: string[];
      IncludeSpaces?: string[];
      SpaceFieldMappings?: ConfluenceSpaceToIndexFieldMapping[];
    }
    export interface ConfluenceSpaceToIndexFieldMapping {
      DataSourceFieldName: string;
      DateFieldFormat?: string;
      IndexFieldName: string;
    }
    export interface ConnectionConfiguration {
      DatabaseHost: string;
      DatabaseName: string;
      DatabasePort: number;
      SecretArn: string;
      TableName: string;
    }
    export interface CustomDocumentEnrichmentConfiguration {
      InlineConfigurations?: InlineCustomDocumentEnrichmentConfiguration[];
      PostExtractionHookConfiguration?: HookConfiguration;
      PreExtractionHookConfiguration?: HookConfiguration;
      RoleArn?: string;
    }
    export interface DataSourceConfiguration {
      ConfluenceConfiguration?: ConfluenceConfiguration;
      DatabaseConfiguration?: DatabaseConfiguration;
      GoogleDriveConfiguration?: GoogleDriveConfiguration;
      OneDriveConfiguration?: OneDriveConfiguration;
      S3Configuration?: S3DataSourceConfiguration;
      SalesforceConfiguration?: SalesforceConfiguration;
      ServiceNowConfiguration?: ServiceNowConfiguration;
      SharePointConfiguration?: SharePointConfiguration;
      WebCrawlerConfiguration?: WebCrawlerConfiguration;
      WorkDocsConfiguration?: WorkDocsConfiguration;
    }
    export interface DataSourceToIndexFieldMapping {
      DataSourceFieldName: string;
      DateFieldFormat?: string;
      IndexFieldName: string;
    }
    export interface DataSourceVpcConfiguration {
      SecurityGroupIds: string[];
      SubnetIds: string[];
    }
    export interface DatabaseConfiguration {
      AclConfiguration?: AclConfiguration;
      ColumnConfiguration: ColumnConfiguration;
      ConnectionConfiguration: ConnectionConfiguration;
      DatabaseEngineType: string;
      SqlConfiguration?: SqlConfiguration;
      VpcConfiguration?: DataSourceVpcConfiguration;
    }
    export interface DocumentAttributeCondition {
      ConditionDocumentAttributeKey: string;
      ConditionOnValue?: DocumentAttributeValue;
      Operator: string;
    }
    export interface DocumentAttributeTarget {
      TargetDocumentAttributeKey: string;
      TargetDocumentAttributeValue?: DocumentAttributeValue;
      TargetDocumentAttributeValueDeletion?: boolean;
    }
    export interface DocumentAttributeValue {
      DateValue?: string;
      LongValue?: number;
      StringListValue?: string[];
      StringValue?: string;
    }
    export interface DocumentsMetadataConfiguration {
      S3Prefix?: string;
    }
    export interface GoogleDriveConfiguration {
      ExcludeMimeTypes?: string[];
      ExcludeSharedDrives?: string[];
      ExcludeUserAccounts?: string[];
      ExclusionPatterns?: string[];
      FieldMappings?: DataSourceToIndexFieldMapping[];
      InclusionPatterns?: string[];
      SecretArn: string;
    }
    export interface HookConfiguration {
      InvocationCondition?: DocumentAttributeCondition;
      LambdaArn: string;
      S3Bucket: string;
    }
    export interface InlineCustomDocumentEnrichmentConfiguration {
      Condition?: DocumentAttributeCondition;
      DocumentContentDeletion?: boolean;
      Target?: DocumentAttributeTarget;
    }
    export interface OneDriveConfiguration {
      DisableLocalGroups?: boolean;
      ExclusionPatterns?: string[];
      FieldMappings?: DataSourceToIndexFieldMapping[];
      InclusionPatterns?: string[];
      OneDriveUsers: OneDriveUsers;
      SecretArn: string;
      TenantDomain: string;
    }
    export interface OneDriveUsers {
      OneDriveUserList?: string[];
      OneDriveUserS3Path?: S3Path;
    }
    export interface ProxyConfiguration {
      Credentials?: string;
      Host: string;
      Port: number;
    }
    export interface S3DataSourceConfiguration {
      AccessControlListConfiguration?: AccessControlListConfiguration;
      BucketName: string;
      DocumentsMetadataConfiguration?: DocumentsMetadataConfiguration;
      ExclusionPatterns?: string[];
      InclusionPatterns?: string[];
      InclusionPrefixes?: string[];
    }
    export interface S3Path {
      Bucket: string;
      Key: string;
    }
    export interface SalesforceChatterFeedConfiguration {
      DocumentDataFieldName: string;
      DocumentTitleFieldName?: string;
      FieldMappings?: DataSourceToIndexFieldMapping[];
      IncludeFilterTypes?: string[];
    }
    export interface SalesforceConfiguration {
      ChatterFeedConfiguration?: SalesforceChatterFeedConfiguration;
      CrawlAttachments?: boolean;
      ExcludeAttachmentFilePatterns?: string[];
      IncludeAttachmentFilePatterns?: string[];
      KnowledgeArticleConfiguration?: SalesforceKnowledgeArticleConfiguration;
      SecretArn: string;
      ServerUrl: string;
      StandardObjectAttachmentConfiguration?: SalesforceStandardObjectAttachmentConfiguration;
      StandardObjectConfigurations?: SalesforceStandardObjectConfiguration[];
    }
    export interface SalesforceCustomKnowledgeArticleTypeConfiguration {
      DocumentDataFieldName: string;
      DocumentTitleFieldName?: string;
      FieldMappings?: DataSourceToIndexFieldMapping[];
      Name: string;
    }
    export interface SalesforceKnowledgeArticleConfiguration {
      CustomKnowledgeArticleTypeConfigurations?: SalesforceCustomKnowledgeArticleTypeConfiguration[];
      IncludedStates: string[];
      StandardKnowledgeArticleTypeConfiguration?: SalesforceStandardKnowledgeArticleTypeConfiguration;
    }
    export interface SalesforceStandardKnowledgeArticleTypeConfiguration {
      DocumentDataFieldName: string;
      DocumentTitleFieldName?: string;
      FieldMappings?: DataSourceToIndexFieldMapping[];
    }
    export interface SalesforceStandardObjectAttachmentConfiguration {
      DocumentTitleFieldName?: string;
      FieldMappings?: DataSourceToIndexFieldMapping[];
    }
    export interface SalesforceStandardObjectConfiguration {
      DocumentDataFieldName: string;
      DocumentTitleFieldName?: string;
      FieldMappings?: DataSourceToIndexFieldMapping[];
      Name: string;
    }
    export interface ServiceNowConfiguration {
      AuthenticationType?: string;
      HostUrl: string;
      KnowledgeArticleConfiguration?: ServiceNowKnowledgeArticleConfiguration;
      SecretArn: string;
      ServiceCatalogConfiguration?: ServiceNowServiceCatalogConfiguration;
      ServiceNowBuildVersion: string;
    }
    export interface ServiceNowKnowledgeArticleConfiguration {
      CrawlAttachments?: boolean;
      DocumentDataFieldName: string;
      DocumentTitleFieldName?: string;
      ExcludeAttachmentFilePatterns?: string[];
      FieldMappings?: DataSourceToIndexFieldMapping[];
      FilterQuery?: string;
      IncludeAttachmentFilePatterns?: string[];
    }
    export interface ServiceNowServiceCatalogConfiguration {
      CrawlAttachments?: boolean;
      DocumentDataFieldName: string;
      DocumentTitleFieldName?: string;
      ExcludeAttachmentFilePatterns?: string[];
      FieldMappings?: DataSourceToIndexFieldMapping[];
      IncludeAttachmentFilePatterns?: string[];
    }
    export interface SharePointConfiguration {
      CrawlAttachments?: boolean;
      DisableLocalGroups?: boolean;
      DocumentTitleFieldName?: string;
      ExclusionPatterns?: string[];
      FieldMappings?: DataSourceToIndexFieldMapping[];
      InclusionPatterns?: string[];
      SecretArn: string;
      SharePointVersion: string;
      SslCertificateS3Path?: S3Path;
      Urls: string[];
      UseChangeLog?: boolean;
      VpcConfiguration?: DataSourceVpcConfiguration;
    }
    export interface SqlConfiguration {
      QueryIdentifiersEnclosingOption?: string;
    }
    export interface WebCrawlerAuthenticationConfiguration {
      BasicAuthentication?: WebCrawlerBasicAuthentication[];
    }
    export interface WebCrawlerBasicAuthentication {
      Credentials: string;
      Host: string;
      Port: number;
    }
    export interface WebCrawlerConfiguration {
      AuthenticationConfiguration?: WebCrawlerAuthenticationConfiguration;
      CrawlDepth?: number;
      MaxContentSizePerPageInMegaBytes?: number;
      MaxLinksPerPage?: number;
      MaxUrlsPerMinuteCrawlRate?: number;
      ProxyConfiguration?: ProxyConfiguration;
      UrlExclusionPatterns?: string[];
      UrlInclusionPatterns?: string[];
      Urls: WebCrawlerUrls;
    }
    export interface WebCrawlerSeedUrlConfiguration {
      SeedUrls: string[];
      WebCrawlerMode?: string;
    }
    export interface WebCrawlerSiteMapsConfiguration {
      SiteMaps: string[];
    }
    export interface WebCrawlerUrls {
      SeedUrlConfiguration?: WebCrawlerSeedUrlConfiguration;
      SiteMapsConfiguration?: WebCrawlerSiteMapsConfiguration;
    }
    export interface WorkDocsConfiguration {
      CrawlComments?: boolean;
      ExclusionPatterns?: string[];
      FieldMappings?: DataSourceToIndexFieldMapping[];
      InclusionPatterns?: string[];
      OrganizationId: string;
      UseChangeLog?: boolean;
    }
  }
  export interface Faq {
    Description?: string;
    FileFormat?: string;
    IndexId: string;
    Name: string;
    RoleArn: string;
    S3Path: Faq.S3Path;
    Tags?: Tag[];
  }
  export namespace Faq {
    export interface Attr {
      Arn: string;
      Id: string;
    }
    export interface S3Path {
      Bucket: string;
      Key: string;
    }
  }
  export interface Index {
    CapacityUnits?: Index.CapacityUnitsConfiguration;
    Description?: string;
    DocumentMetadataConfigurations?: Index.DocumentMetadataConfiguration[];
    Edition: string;
    Name: string;
    RoleArn: string;
    ServerSideEncryptionConfiguration?: Index.ServerSideEncryptionConfiguration;
    Tags?: Tag[];
    UserContextPolicy?: string;
    UserTokenConfigurations?: Index.UserTokenConfiguration[];
  }
  export namespace Index {
    export interface Attr {
      Arn: string;
      Id: string;
    }
    export interface CapacityUnitsConfiguration {
      QueryCapacityUnits: number;
      StorageCapacityUnits: number;
    }
    export interface DocumentMetadataConfiguration {
      Name: string;
      Relevance?: Relevance;
      Search?: Search;
      Type: string;
    }
    export interface JsonTokenTypeConfiguration {
      GroupAttributeField: string;
      UserNameAttributeField: string;
    }
    export interface JwtTokenTypeConfiguration {
      ClaimRegex?: string;
      GroupAttributeField?: string;
      Issuer?: string;
      KeyLocation: string;
      SecretManagerArn?: string;
      URL?: string;
      UserNameAttributeField?: string;
    }
    export interface Relevance {
      Duration?: string;
      Freshness?: boolean;
      Importance?: number;
      RankOrder?: string;
      ValueImportanceItems?: ValueImportanceItem[];
    }
    export interface Search {
      Displayable?: boolean;
      Facetable?: boolean;
      Searchable?: boolean;
      Sortable?: boolean;
    }
    export interface ServerSideEncryptionConfiguration {
      KmsKeyId?: string;
    }
    export interface UserTokenConfiguration {
      JsonTokenTypeConfiguration?: JsonTokenTypeConfiguration;
      JwtTokenTypeConfiguration?: JwtTokenTypeConfiguration;
    }
    export interface ValueImportanceItem {
      Key?: string;
      Value?: number;
    }
  }
}
export namespace KendraRanking {
  export interface ExecutionPlan {
    CapacityUnits?: ExecutionPlan.CapacityUnitsConfiguration;
    Description?: string;
    Name: string;
    Tags?: Tag[];
  }
  export namespace ExecutionPlan {
    export interface Attr {
      Arn: string;
      Id: string;
    }
    export interface CapacityUnitsConfiguration {
      RescoreCapacityUnits: number;
    }
  }
}
export namespace Kinesis {
  export interface Stream {
    Name?: string;
    RetentionPeriodHours?: number;
    ShardCount?: number;
    StreamEncryption?: Stream.StreamEncryption;
    StreamModeDetails?: Stream.StreamModeDetails;
    Tags?: Tag[];
  }
  export namespace Stream {
    export interface Attr {
      Arn: string;
    }
    export interface StreamEncryption {
      EncryptionType: string;
      KeyId: string;
    }
    export interface StreamModeDetails {
      StreamMode: string;
    }
  }
  export interface StreamConsumer {
    ConsumerName: string;
    StreamARN: string;
  }
}
export namespace KinesisAnalytics {
  export interface Application {
    ApplicationCode?: string;
    ApplicationDescription?: string;
    ApplicationName?: string;
    Inputs: Application.Input[];
  }
  export namespace Application {
    export interface Attr {}
    export interface CSVMappingParameters {
      RecordColumnDelimiter: string;
      RecordRowDelimiter: string;
    }
    export interface Input {
      InputParallelism?: InputParallelism;
      InputProcessingConfiguration?: InputProcessingConfiguration;
      InputSchema: InputSchema;
      KinesisFirehoseInput?: KinesisFirehoseInput;
      KinesisStreamsInput?: KinesisStreamsInput;
      NamePrefix: string;
    }
    export interface InputLambdaProcessor {
      ResourceARN: string;
      RoleARN: string;
    }
    export interface InputParallelism {
      Count?: number;
    }
    export interface InputProcessingConfiguration {
      InputLambdaProcessor?: InputLambdaProcessor;
    }
    export interface InputSchema {
      RecordColumns: RecordColumn[];
      RecordEncoding?: string;
      RecordFormat: RecordFormat;
    }
    export interface JSONMappingParameters {
      RecordRowPath: string;
    }
    export interface KinesisFirehoseInput {
      ResourceARN: string;
      RoleARN: string;
    }
    export interface KinesisStreamsInput {
      ResourceARN: string;
      RoleARN: string;
    }
    export interface MappingParameters {
      CSVMappingParameters?: CSVMappingParameters;
      JSONMappingParameters?: JSONMappingParameters;
    }
    export interface RecordColumn {
      Mapping?: string;
      Name: string;
      SqlType: string;
    }
    export interface RecordFormat {
      MappingParameters?: MappingParameters;
      RecordFormatType: string;
    }
  }
  export interface ApplicationOutput {
    ApplicationName: string;
    Output: ApplicationOutput.Output;
  }
  export namespace ApplicationOutput {
    export interface Attr {}
    export interface DestinationSchema {
      RecordFormatType?: string;
    }
    export interface KinesisFirehoseOutput {
      ResourceARN: string;
      RoleARN: string;
    }
    export interface KinesisStreamsOutput {
      ResourceARN: string;
      RoleARN: string;
    }
    export interface LambdaOutput {
      ResourceARN: string;
      RoleARN: string;
    }
    export interface Output {
      DestinationSchema: DestinationSchema;
      KinesisFirehoseOutput?: KinesisFirehoseOutput;
      KinesisStreamsOutput?: KinesisStreamsOutput;
      LambdaOutput?: LambdaOutput;
      Name?: string;
    }
  }
  export interface ApplicationReferenceDataSource {
    ApplicationName: string;
    ReferenceDataSource: ApplicationReferenceDataSource.ReferenceDataSource;
  }
  export namespace ApplicationReferenceDataSource {
    export interface Attr {}
    export interface CSVMappingParameters {
      RecordColumnDelimiter: string;
      RecordRowDelimiter: string;
    }
    export interface JSONMappingParameters {
      RecordRowPath: string;
    }
    export interface MappingParameters {
      CSVMappingParameters?: CSVMappingParameters;
      JSONMappingParameters?: JSONMappingParameters;
    }
    export interface RecordColumn {
      Mapping?: string;
      Name: string;
      SqlType: string;
    }
    export interface RecordFormat {
      MappingParameters?: MappingParameters;
      RecordFormatType: string;
    }
    export interface ReferenceDataSource {
      ReferenceSchema: ReferenceSchema;
      S3ReferenceDataSource?: S3ReferenceDataSource;
      TableName?: string;
    }
    export interface ReferenceSchema {
      RecordColumns: RecordColumn[];
      RecordEncoding?: string;
      RecordFormat: RecordFormat;
    }
    export interface S3ReferenceDataSource {
      BucketARN: string;
      FileKey: string;
      ReferenceRoleARN: string;
    }
  }
}
export namespace KinesisAnalyticsV2 {
  export interface Application {
    ApplicationConfiguration?: Application.ApplicationConfiguration;
    ApplicationDescription?: string;
    ApplicationMaintenanceConfiguration?: Application.ApplicationMaintenanceConfiguration;
    ApplicationMode?: string;
    ApplicationName?: string;
    RunConfiguration?: Application.RunConfiguration;
    RuntimeEnvironment: string;
    ServiceExecutionRole: string;
    Tags?: Tag[];
  }
  export namespace Application {
    export interface Attr {}
    export interface ApplicationCodeConfiguration {
      CodeContent: CodeContent;
      CodeContentType: string;
    }
    export interface ApplicationConfiguration {
      ApplicationCodeConfiguration?: ApplicationCodeConfiguration;
      ApplicationSnapshotConfiguration?: ApplicationSnapshotConfiguration;
      EnvironmentProperties?: EnvironmentProperties;
      FlinkApplicationConfiguration?: FlinkApplicationConfiguration;
      SqlApplicationConfiguration?: SqlApplicationConfiguration;
      VpcConfigurations?: VpcConfiguration[];
      ZeppelinApplicationConfiguration?: ZeppelinApplicationConfiguration;
    }
    export interface ApplicationMaintenanceConfiguration {
      ApplicationMaintenanceWindowStartTime: string;
    }
    export interface ApplicationRestoreConfiguration {
      ApplicationRestoreType: string;
      SnapshotName?: string;
    }
    export interface ApplicationSnapshotConfiguration {
      SnapshotsEnabled: boolean;
    }
    export interface CSVMappingParameters {
      RecordColumnDelimiter: string;
      RecordRowDelimiter: string;
    }
    export interface CatalogConfiguration {
      GlueDataCatalogConfiguration?: GlueDataCatalogConfiguration;
    }
    export interface CheckpointConfiguration {
      CheckpointInterval?: number;
      CheckpointingEnabled?: boolean;
      ConfigurationType: string;
      MinPauseBetweenCheckpoints?: number;
    }
    export interface CodeContent {
      S3ContentLocation?: S3ContentLocation;
      TextContent?: string;
      ZipFileContent?: string;
    }
    export interface CustomArtifactConfiguration {
      ArtifactType: string;
      MavenReference?: MavenReference;
      S3ContentLocation?: S3ContentLocation;
    }
    export interface DeployAsApplicationConfiguration {
      S3ContentLocation: S3ContentBaseLocation;
    }
    export interface EnvironmentProperties {
      PropertyGroups?: PropertyGroup[];
    }
    export interface FlinkApplicationConfiguration {
      CheckpointConfiguration?: CheckpointConfiguration;
      MonitoringConfiguration?: MonitoringConfiguration;
      ParallelismConfiguration?: ParallelismConfiguration;
    }
    export interface FlinkRunConfiguration {
      AllowNonRestoredState?: boolean;
    }
    export interface GlueDataCatalogConfiguration {
      DatabaseARN?: string;
    }
    export interface Input {
      InputParallelism?: InputParallelism;
      InputProcessingConfiguration?: InputProcessingConfiguration;
      InputSchema: InputSchema;
      KinesisFirehoseInput?: KinesisFirehoseInput;
      KinesisStreamsInput?: KinesisStreamsInput;
      NamePrefix: string;
    }
    export interface InputLambdaProcessor {
      ResourceARN: string;
    }
    export interface InputParallelism {
      Count?: number;
    }
    export interface InputProcessingConfiguration {
      InputLambdaProcessor?: InputLambdaProcessor;
    }
    export interface InputSchema {
      RecordColumns: RecordColumn[];
      RecordEncoding?: string;
      RecordFormat: RecordFormat;
    }
    export interface JSONMappingParameters {
      RecordRowPath: string;
    }
    export interface KinesisFirehoseInput {
      ResourceARN: string;
    }
    export interface KinesisStreamsInput {
      ResourceARN: string;
    }
    export interface MappingParameters {
      CSVMappingParameters?: CSVMappingParameters;
      JSONMappingParameters?: JSONMappingParameters;
    }
    export interface MavenReference {
      ArtifactId: string;
      GroupId: string;
      Version: string;
    }
    export interface MonitoringConfiguration {
      ConfigurationType: string;
      LogLevel?: string;
      MetricsLevel?: string;
    }
    export interface ParallelismConfiguration {
      AutoScalingEnabled?: boolean;
      ConfigurationType: string;
      Parallelism?: number;
      ParallelismPerKPU?: number;
    }
    export interface PropertyGroup {
      PropertyGroupId?: string;
      PropertyMap?: Record<string, string>;
    }
    export interface RecordColumn {
      Mapping?: string;
      Name: string;
      SqlType: string;
    }
    export interface RecordFormat {
      MappingParameters?: MappingParameters;
      RecordFormatType: string;
    }
    export interface RunConfiguration {
      ApplicationRestoreConfiguration?: ApplicationRestoreConfiguration;
      FlinkRunConfiguration?: FlinkRunConfiguration;
    }
    export interface S3ContentBaseLocation {
      BasePath?: string;
      BucketARN: string;
    }
    export interface S3ContentLocation {
      BucketARN: string;
      FileKey: string;
      ObjectVersion?: string;
    }
    export interface SqlApplicationConfiguration {
      Inputs?: Input[];
    }
    export interface VpcConfiguration {
      SecurityGroupIds: string[];
      SubnetIds: string[];
    }
    export interface ZeppelinApplicationConfiguration {
      CatalogConfiguration?: CatalogConfiguration;
      CustomArtifactsConfiguration?: CustomArtifactConfiguration[];
      DeployAsApplicationConfiguration?: DeployAsApplicationConfiguration;
      MonitoringConfiguration?: ZeppelinMonitoringConfiguration;
    }
    export interface ZeppelinMonitoringConfiguration {
      LogLevel?: string;
    }
  }
  export interface ApplicationCloudWatchLoggingOption {
    ApplicationName: string;
    CloudWatchLoggingOption: ApplicationCloudWatchLoggingOption.CloudWatchLoggingOption;
  }
  export namespace ApplicationCloudWatchLoggingOption {
    export interface Attr {}
    export interface CloudWatchLoggingOption {
      LogStreamARN: string;
    }
  }
  export interface ApplicationOutput {
    ApplicationName: string;
    Output: ApplicationOutput.Output;
  }
  export namespace ApplicationOutput {
    export interface Attr {}
    export interface DestinationSchema {
      RecordFormatType?: string;
    }
    export interface KinesisFirehoseOutput {
      ResourceARN: string;
    }
    export interface KinesisStreamsOutput {
      ResourceARN: string;
    }
    export interface LambdaOutput {
      ResourceARN: string;
    }
    export interface Output {
      DestinationSchema: DestinationSchema;
      KinesisFirehoseOutput?: KinesisFirehoseOutput;
      KinesisStreamsOutput?: KinesisStreamsOutput;
      LambdaOutput?: LambdaOutput;
      Name?: string;
    }
  }
  export interface ApplicationReferenceDataSource {
    ApplicationName: string;
    ReferenceDataSource: ApplicationReferenceDataSource.ReferenceDataSource;
  }
  export namespace ApplicationReferenceDataSource {
    export interface Attr {}
    export interface CSVMappingParameters {
      RecordColumnDelimiter: string;
      RecordRowDelimiter: string;
    }
    export interface JSONMappingParameters {
      RecordRowPath: string;
    }
    export interface MappingParameters {
      CSVMappingParameters?: CSVMappingParameters;
      JSONMappingParameters?: JSONMappingParameters;
    }
    export interface RecordColumn {
      Mapping?: string;
      Name: string;
      SqlType: string;
    }
    export interface RecordFormat {
      MappingParameters?: MappingParameters;
      RecordFormatType: string;
    }
    export interface ReferenceDataSource {
      ReferenceSchema: ReferenceSchema;
      S3ReferenceDataSource?: S3ReferenceDataSource;
      TableName?: string;
    }
    export interface ReferenceSchema {
      RecordColumns: RecordColumn[];
      RecordEncoding?: string;
      RecordFormat: RecordFormat;
    }
    export interface S3ReferenceDataSource {
      BucketARN: string;
      FileKey: string;
    }
  }
}
export namespace KinesisFirehose {
  export interface DeliveryStream {
    AmazonOpenSearchServerlessDestinationConfiguration?: DeliveryStream.AmazonOpenSearchServerlessDestinationConfiguration;
    AmazonopensearchserviceDestinationConfiguration?: DeliveryStream.AmazonopensearchserviceDestinationConfiguration;
    DeliveryStreamEncryptionConfigurationInput?: DeliveryStream.DeliveryStreamEncryptionConfigurationInput;
    DeliveryStreamName?: string;
    DeliveryStreamType?: string;
    ElasticsearchDestinationConfiguration?: DeliveryStream.ElasticsearchDestinationConfiguration;
    ExtendedS3DestinationConfiguration?: DeliveryStream.ExtendedS3DestinationConfiguration;
    HttpEndpointDestinationConfiguration?: DeliveryStream.HttpEndpointDestinationConfiguration;
    KinesisStreamSourceConfiguration?: DeliveryStream.KinesisStreamSourceConfiguration;
    RedshiftDestinationConfiguration?: DeliveryStream.RedshiftDestinationConfiguration;
    S3DestinationConfiguration?: DeliveryStream.S3DestinationConfiguration;
    SplunkDestinationConfiguration?: DeliveryStream.SplunkDestinationConfiguration;
    Tags?: Tag[];
  }
  export namespace DeliveryStream {
    export interface Attr {
      Arn: string;
    }
    export interface AmazonOpenSearchServerlessBufferingHints {
      IntervalInSeconds?: number;
      SizeInMBs?: number;
    }
    export interface AmazonOpenSearchServerlessDestinationConfiguration {
      BufferingHints?: AmazonOpenSearchServerlessBufferingHints;
      CloudWatchLoggingOptions?: CloudWatchLoggingOptions;
      CollectionEndpoint?: string;
      IndexName: string;
      ProcessingConfiguration?: ProcessingConfiguration;
      RetryOptions?: AmazonOpenSearchServerlessRetryOptions;
      RoleARN: string;
      S3BackupMode?: string;
      S3Configuration: S3DestinationConfiguration;
      VpcConfiguration?: VpcConfiguration;
    }
    export interface AmazonOpenSearchServerlessRetryOptions {
      DurationInSeconds?: number;
    }
    export interface AmazonopensearchserviceBufferingHints {
      IntervalInSeconds?: number;
      SizeInMBs?: number;
    }
    export interface AmazonopensearchserviceDestinationConfiguration {
      BufferingHints?: AmazonopensearchserviceBufferingHints;
      CloudWatchLoggingOptions?: CloudWatchLoggingOptions;
      ClusterEndpoint?: string;
      DomainARN?: string;
      IndexName: string;
      IndexRotationPeriod?: string;
      ProcessingConfiguration?: ProcessingConfiguration;
      RetryOptions?: AmazonopensearchserviceRetryOptions;
      RoleARN: string;
      S3BackupMode?: string;
      S3Configuration: S3DestinationConfiguration;
      TypeName?: string;
      VpcConfiguration?: VpcConfiguration;
    }
    export interface AmazonopensearchserviceRetryOptions {
      DurationInSeconds?: number;
    }
    export interface BufferingHints {
      IntervalInSeconds?: number;
      SizeInMBs?: number;
    }
    export interface CloudWatchLoggingOptions {
      Enabled?: boolean;
      LogGroupName?: string;
      LogStreamName?: string;
    }
    export interface CopyCommand {
      CopyOptions?: string;
      DataTableColumns?: string;
      DataTableName: string;
    }
    export interface DataFormatConversionConfiguration {
      Enabled?: boolean;
      InputFormatConfiguration?: InputFormatConfiguration;
      OutputFormatConfiguration?: OutputFormatConfiguration;
      SchemaConfiguration?: SchemaConfiguration;
    }
    export interface DeliveryStreamEncryptionConfigurationInput {
      KeyARN?: string;
      KeyType: string;
    }
    export interface Deserializer {
      HiveJsonSerDe?: HiveJsonSerDe;
      OpenXJsonSerDe?: OpenXJsonSerDe;
    }
    export interface DynamicPartitioningConfiguration {
      Enabled?: boolean;
      RetryOptions?: RetryOptions;
    }
    export interface ElasticsearchBufferingHints {
      IntervalInSeconds?: number;
      SizeInMBs?: number;
    }
    export interface ElasticsearchDestinationConfiguration {
      BufferingHints?: ElasticsearchBufferingHints;
      CloudWatchLoggingOptions?: CloudWatchLoggingOptions;
      ClusterEndpoint?: string;
      DomainARN?: string;
      IndexName: string;
      IndexRotationPeriod?: string;
      ProcessingConfiguration?: ProcessingConfiguration;
      RetryOptions?: ElasticsearchRetryOptions;
      RoleARN: string;
      S3BackupMode?: string;
      S3Configuration: S3DestinationConfiguration;
      TypeName?: string;
      VpcConfiguration?: VpcConfiguration;
    }
    export interface ElasticsearchRetryOptions {
      DurationInSeconds?: number;
    }
    export interface EncryptionConfiguration {
      KMSEncryptionConfig?: KMSEncryptionConfig;
      NoEncryptionConfig?: string;
    }
    export interface ExtendedS3DestinationConfiguration {
      BucketARN: string;
      BufferingHints?: BufferingHints;
      CloudWatchLoggingOptions?: CloudWatchLoggingOptions;
      CompressionFormat?: string;
      DataFormatConversionConfiguration?: DataFormatConversionConfiguration;
      DynamicPartitioningConfiguration?: DynamicPartitioningConfiguration;
      EncryptionConfiguration?: EncryptionConfiguration;
      ErrorOutputPrefix?: string;
      Prefix?: string;
      ProcessingConfiguration?: ProcessingConfiguration;
      RoleARN: string;
      S3BackupConfiguration?: S3DestinationConfiguration;
      S3BackupMode?: string;
    }
    export interface HiveJsonSerDe {
      TimestampFormats?: string[];
    }
    export interface HttpEndpointCommonAttribute {
      AttributeName: string;
      AttributeValue: string;
    }
    export interface HttpEndpointConfiguration {
      AccessKey?: string;
      Name?: string;
      Url: string;
    }
    export interface HttpEndpointDestinationConfiguration {
      BufferingHints?: BufferingHints;
      CloudWatchLoggingOptions?: CloudWatchLoggingOptions;
      EndpointConfiguration: HttpEndpointConfiguration;
      ProcessingConfiguration?: ProcessingConfiguration;
      RequestConfiguration?: HttpEndpointRequestConfiguration;
      RetryOptions?: RetryOptions;
      RoleARN?: string;
      S3BackupMode?: string;
      S3Configuration: S3DestinationConfiguration;
    }
    export interface HttpEndpointRequestConfiguration {
      CommonAttributes?: HttpEndpointCommonAttribute[];
      ContentEncoding?: string;
    }
    export interface InputFormatConfiguration {
      Deserializer?: Deserializer;
    }
    export interface KMSEncryptionConfig {
      AWSKMSKeyARN: string;
    }
    export interface KinesisStreamSourceConfiguration {
      KinesisStreamARN: string;
      RoleARN: string;
    }
    export interface OpenXJsonSerDe {
      CaseInsensitive?: boolean;
      ColumnToJsonKeyMappings?: Record<string, string>;
      ConvertDotsInJsonKeysToUnderscores?: boolean;
    }
    export interface OrcSerDe {
      BlockSizeBytes?: number;
      BloomFilterColumns?: string[];
      BloomFilterFalsePositiveProbability?: number;
      Compression?: string;
      DictionaryKeyThreshold?: number;
      EnablePadding?: boolean;
      FormatVersion?: string;
      PaddingTolerance?: number;
      RowIndexStride?: number;
      StripeSizeBytes?: number;
    }
    export interface OutputFormatConfiguration {
      Serializer?: Serializer;
    }
    export interface ParquetSerDe {
      BlockSizeBytes?: number;
      Compression?: string;
      EnableDictionaryCompression?: boolean;
      MaxPaddingBytes?: number;
      PageSizeBytes?: number;
      WriterVersion?: string;
    }
    export interface ProcessingConfiguration {
      Enabled?: boolean;
      Processors?: Processor[];
    }
    export interface Processor {
      Parameters?: ProcessorParameter[];
      Type: string;
    }
    export interface ProcessorParameter {
      ParameterName: string;
      ParameterValue: string;
    }
    export interface RedshiftDestinationConfiguration {
      CloudWatchLoggingOptions?: CloudWatchLoggingOptions;
      ClusterJDBCURL: string;
      CopyCommand: CopyCommand;
      Password: string;
      ProcessingConfiguration?: ProcessingConfiguration;
      RetryOptions?: RedshiftRetryOptions;
      RoleARN: string;
      S3BackupConfiguration?: S3DestinationConfiguration;
      S3BackupMode?: string;
      S3Configuration: S3DestinationConfiguration;
      Username: string;
    }
    export interface RedshiftRetryOptions {
      DurationInSeconds?: number;
    }
    export interface RetryOptions {
      DurationInSeconds?: number;
    }
    export interface S3DestinationConfiguration {
      BucketARN: string;
      BufferingHints?: BufferingHints;
      CloudWatchLoggingOptions?: CloudWatchLoggingOptions;
      CompressionFormat?: string;
      EncryptionConfiguration?: EncryptionConfiguration;
      ErrorOutputPrefix?: string;
      Prefix?: string;
      RoleARN: string;
    }
    export interface SchemaConfiguration {
      CatalogId?: string;
      DatabaseName?: string;
      Region?: string;
      RoleARN?: string;
      TableName?: string;
      VersionId?: string;
    }
    export interface Serializer {
      OrcSerDe?: OrcSerDe;
      ParquetSerDe?: ParquetSerDe;
    }
    export interface SplunkDestinationConfiguration {
      CloudWatchLoggingOptions?: CloudWatchLoggingOptions;
      HECAcknowledgmentTimeoutInSeconds?: number;
      HECEndpoint: string;
      HECEndpointType: string;
      HECToken: string;
      ProcessingConfiguration?: ProcessingConfiguration;
      RetryOptions?: SplunkRetryOptions;
      S3BackupMode?: string;
      S3Configuration: S3DestinationConfiguration;
    }
    export interface SplunkRetryOptions {
      DurationInSeconds?: number;
    }
    export interface VpcConfiguration {
      RoleARN: string;
      SecurityGroupIds: string[];
      SubnetIds: string[];
    }
  }
}
export namespace KinesisVideo {
  export interface SignalingChannel {
    MessageTtlSeconds?: number;
    Name?: string;
    Tags?: Tag[];
    Type?: string;
  }
  export interface Stream {
    DataRetentionInHours?: number;
    DeviceName?: string;
    KmsKeyId?: string;
    MediaType?: string;
    Name?: string;
    Tags?: Tag[];
  }
}
export namespace LakeFormation {
  export interface DataCellsFilter {
    ColumnNames?: string[];
    ColumnWildcard?: DataCellsFilter.ColumnWildcard;
    DatabaseName: string;
    Name: string;
    RowFilter?: DataCellsFilter.RowFilter;
    TableCatalogId: string;
    TableName: string;
  }
  export namespace DataCellsFilter {
    export interface Attr {}
    export interface ColumnWildcard {
      ExcludedColumnNames?: string[];
    }
    export interface RowFilter {
      AllRowsWildcard?: any;
      FilterExpression?: string;
    }
  }
  export interface DataLakeSettings {
    Admins?: DataLakeSettings.Admins;
    TrustedResourceOwners?: string[];
  }
  export namespace DataLakeSettings {
    export interface Attr {}
    export interface Admins {}
    export interface DataLakePrincipal {
      DataLakePrincipalIdentifier?: string;
    }
  }
  export interface Permissions {
    DataLakePrincipal: Permissions.DataLakePrincipal;
    Permissions?: string[];
    PermissionsWithGrantOption?: string[];
    Resource: Permissions.Resource;
  }
  export namespace Permissions {
    export interface Attr {}
    export interface ColumnWildcard {
      ExcludedColumnNames?: string[];
    }
    export interface DataLakePrincipal {
      DataLakePrincipalIdentifier?: string;
    }
    export interface DataLocationResource {
      CatalogId?: string;
      S3Resource?: string;
    }
    export interface DatabaseResource {
      CatalogId?: string;
      Name?: string;
    }
    export interface Resource {
      DataLocationResource?: DataLocationResource;
      DatabaseResource?: DatabaseResource;
      TableResource?: TableResource;
      TableWithColumnsResource?: TableWithColumnsResource;
    }
    export interface TableResource {
      CatalogId?: string;
      DatabaseName?: string;
      Name?: string;
      TableWildcard?: TableWildcard;
    }
    export interface TableWildcard {}
    export interface TableWithColumnsResource {
      CatalogId?: string;
      ColumnNames?: string[];
      ColumnWildcard?: ColumnWildcard;
      DatabaseName?: string;
      Name?: string;
    }
  }
  export interface PrincipalPermissions {
    Catalog?: string;
    Permissions: string[];
    PermissionsWithGrantOption: string[];
    Principal: PrincipalPermissions.DataLakePrincipal;
    Resource: PrincipalPermissions.Resource;
  }
  export namespace PrincipalPermissions {
    export interface Attr {
      PrincipalIdentifier: string;
      ResourceIdentifier: string;
    }
    export interface ColumnWildcard {
      ExcludedColumnNames?: string[];
    }
    export interface DataCellsFilterResource {
      DatabaseName: string;
      Name: string;
      TableCatalogId: string;
      TableName: string;
    }
    export interface DataLakePrincipal {
      DataLakePrincipalIdentifier?: string;
    }
    export interface DataLocationResource {
      CatalogId: string;
      ResourceArn: string;
    }
    export interface DatabaseResource {
      CatalogId: string;
      Name: string;
    }
    export interface LFTag {
      TagKey?: string;
      TagValues?: string[];
    }
    export interface LFTagKeyResource {
      CatalogId: string;
      TagKey: string;
      TagValues: string[];
    }
    export interface LFTagPolicyResource {
      CatalogId: string;
      Expression: LFTag[];
      ResourceType: string;
    }
    export interface Resource {
      Catalog?: any;
      DataCellsFilter?: DataCellsFilterResource;
      DataLocation?: DataLocationResource;
      Database?: DatabaseResource;
      LFTag?: LFTagKeyResource;
      LFTagPolicy?: LFTagPolicyResource;
      Table?: TableResource;
      TableWithColumns?: TableWithColumnsResource;
    }
    export interface TableResource {
      CatalogId: string;
      DatabaseName: string;
      Name?: string;
      TableWildcard?: any;
    }
    export interface TableWithColumnsResource {
      CatalogId: string;
      ColumnNames?: string[];
      ColumnWildcard?: ColumnWildcard;
      DatabaseName: string;
      Name: string;
    }
  }
  export interface Resource {
    ResourceArn: string;
    RoleArn?: string;
    UseServiceLinkedRole: boolean;
  }
  export interface Tag {
    CatalogId?: string;
    TagKey: string;
    TagValues: string[];
  }
  export interface TagAssociation {
    LFTags: TagAssociation.LFTagPair[];
    Resource: TagAssociation.Resource;
  }
  export namespace TagAssociation {
    export interface Attr {
      ResourceIdentifier: string;
      TagsIdentifier: string;
    }
    export interface DatabaseResource {
      CatalogId: string;
      Name: string;
    }
    export interface LFTagPair {
      CatalogId: string;
      TagKey: string;
      TagValues: string[];
    }
    export interface Resource {
      Catalog?: any;
      Database?: DatabaseResource;
      Table?: TableResource;
      TableWithColumns?: TableWithColumnsResource;
    }
    export interface TableResource {
      CatalogId: string;
      DatabaseName: string;
      Name?: string;
      TableWildcard?: any;
    }
    export interface TableWithColumnsResource {
      CatalogId: string;
      ColumnNames: string[];
      DatabaseName: string;
      Name: string;
    }
  }
}
export namespace Lambda {
  export interface Alias {
    Description?: string;
    FunctionName: string;
    FunctionVersion: string;
    Name: string;
    ProvisionedConcurrencyConfig?: Alias.ProvisionedConcurrencyConfiguration;
    RoutingConfig?: Alias.AliasRoutingConfiguration;
  }
  export namespace Alias {
    export interface Attr {}
    export interface AliasRoutingConfiguration {
      AdditionalVersionWeights: VersionWeight[];
    }
    export interface ProvisionedConcurrencyConfiguration {
      ProvisionedConcurrentExecutions: number;
    }
    export interface VersionWeight {
      FunctionVersion: string;
      FunctionWeight: number;
    }
  }
  export interface CodeSigningConfig {
    AllowedPublishers: CodeSigningConfig.AllowedPublishers;
    CodeSigningPolicies?: CodeSigningConfig.CodeSigningPolicies;
    Description?: string;
  }
  export namespace CodeSigningConfig {
    export interface Attr {
      CodeSigningConfigArn: string;
      CodeSigningConfigId: string;
    }
    export interface AllowedPublishers {
      SigningProfileVersionArns: string[];
    }
    export interface CodeSigningPolicies {
      UntrustedArtifactOnDeployment: string;
    }
  }
  export interface EventInvokeConfig {
    DestinationConfig?: EventInvokeConfig.DestinationConfig;
    FunctionName: string;
    MaximumEventAgeInSeconds?: number;
    MaximumRetryAttempts?: number;
    Qualifier: string;
  }
  export namespace EventInvokeConfig {
    export interface Attr {}
    export interface DestinationConfig {
      OnFailure?: OnFailure;
      OnSuccess?: OnSuccess;
    }
    export interface OnFailure {
      Destination: string;
    }
    export interface OnSuccess {
      Destination: string;
    }
  }
  export interface EventSourceMapping {
    AmazonManagedKafkaEventSourceConfig?: EventSourceMapping.AmazonManagedKafkaEventSourceConfig;
    BatchSize?: number;
    BisectBatchOnFunctionError?: boolean;
    DestinationConfig?: EventSourceMapping.DestinationConfig;
    Enabled?: boolean;
    EventSourceArn?: string;
    FilterCriteria?: EventSourceMapping.FilterCriteria;
    FunctionName: string;
    FunctionResponseTypes?: string[];
    MaximumBatchingWindowInSeconds?: number;
    MaximumRecordAgeInSeconds?: number;
    MaximumRetryAttempts?: number;
    ParallelizationFactor?: number;
    Queues?: string[];
    ScalingConfig?: EventSourceMapping.ScalingConfig;
    SelfManagedEventSource?: EventSourceMapping.SelfManagedEventSource;
    SelfManagedKafkaEventSourceConfig?: EventSourceMapping.SelfManagedKafkaEventSourceConfig;
    SourceAccessConfigurations?: EventSourceMapping.SourceAccessConfiguration[];
    StartingPosition?: string;
    StartingPositionTimestamp?: number;
    Topics?: string[];
    TumblingWindowInSeconds?: number;
  }
  export namespace EventSourceMapping {
    export interface Attr {
      Id: string;
    }
    export interface AmazonManagedKafkaEventSourceConfig {
      ConsumerGroupId?: string;
    }
    export interface DestinationConfig {
      OnFailure?: OnFailure;
    }
    export interface Endpoints {
      KafkaBootstrapServers?: string[];
    }
    export interface Filter {
      Pattern?: string;
    }
    export interface FilterCriteria {
      Filters?: Filter[];
    }
    export interface OnFailure {
      Destination?: string;
    }
    export interface ScalingConfig {
      MaximumConcurrency?: number;
    }
    export interface SelfManagedEventSource {
      Endpoints?: Endpoints;
    }
    export interface SelfManagedKafkaEventSourceConfig {
      ConsumerGroupId?: string;
    }
    export interface SourceAccessConfiguration {
      Type?: string;
      URI?: string;
    }
  }
  export interface Function {
    Architectures?: string[];
    Code: Function.Code;
    CodeSigningConfigArn?: string;
    DeadLetterConfig?: Function.DeadLetterConfig;
    Description?: string;
    Environment?: Function.Environment;
    EphemeralStorage?: Function.EphemeralStorage;
    FileSystemConfigs?: Function.FileSystemConfig[];
    FunctionName?: string;
    Handler?: string;
    ImageConfig?: Function.ImageConfig;
    KmsKeyArn?: string;
    Layers?: string[];
    MemorySize?: number;
    PackageType?: string;
    ReservedConcurrentExecutions?: number;
    Role: string;
    Runtime?: string;
    SnapStart?: Function.SnapStart;
    Tags?: Tag[];
    Timeout?: number;
    TracingConfig?: Function.TracingConfig;
    VpcConfig?: Function.VpcConfig;
  }
  export namespace Function {
    export interface Attr {
      Arn: string;
      "SnapStartResponse.ApplyOn": string;
      "SnapStartResponse.OptimizationStatus": string;
    }
    export interface Code {
      ImageUri?: string;
      S3Bucket?: string;
      S3Key?: string;
      S3ObjectVersion?: string;
      ZipFile?: string;
    }
    export interface DeadLetterConfig {
      TargetArn?: string;
    }
    export interface Environment {
      Variables?: Record<string, string>;
    }
    export interface EphemeralStorage {
      Size: number;
    }
    export interface FileSystemConfig {
      Arn: string;
      LocalMountPath: string;
    }
    export interface ImageConfig {
      Command?: string[];
      EntryPoint?: string[];
      WorkingDirectory?: string;
    }
    export interface SnapStart {
      ApplyOn: string;
    }
    export interface SnapStartResponse {
      ApplyOn?: string;
      OptimizationStatus?: string;
    }
    export interface TracingConfig {
      Mode?: string;
    }
    export interface VpcConfig {
      SecurityGroupIds?: string[];
      SubnetIds?: string[];
    }
  }
  export interface LayerVersion {
    CompatibleArchitectures?: string[];
    CompatibleRuntimes?: string[];
    Content: LayerVersion.Content;
    Description?: string;
    LayerName?: string;
    LicenseInfo?: string;
  }
  export namespace LayerVersion {
    export interface Attr {}
    export interface Content {
      S3Bucket: string;
      S3Key: string;
      S3ObjectVersion?: string;
    }
  }
  export interface LayerVersionPermission {
    Action: string;
    LayerVersionArn: string;
    OrganizationId?: string;
    Principal: string;
  }
  export interface Permission {
    Action: string;
    EventSourceToken?: string;
    FunctionName: string;
    FunctionUrlAuthType?: string;
    Principal: string;
    PrincipalOrgID?: string;
    SourceAccount?: string;
    SourceArn?: string;
  }
  export interface Url {
    AuthType: string;
    Cors?: Url.Cors;
    InvokeMode?: string;
    Qualifier?: string;
    TargetFunctionArn: string;
  }
  export namespace Url {
    export interface Attr {
      FunctionArn: string;
      FunctionUrl: string;
    }
    export interface Cors {
      AllowCredentials?: boolean;
      AllowHeaders?: string[];
      AllowMethods?: string[];
      AllowOrigins?: string[];
      ExposeHeaders?: string[];
      MaxAge?: number;
    }
  }
  export interface Version {
    CodeSha256?: string;
    Description?: string;
    FunctionName: string;
    ProvisionedConcurrencyConfig?: Version.ProvisionedConcurrencyConfiguration;
  }
  export namespace Version {
    export interface Attr {
      Version: string;
    }
    export interface ProvisionedConcurrencyConfiguration {
      ProvisionedConcurrentExecutions: number;
    }
  }
}
export namespace Lex {
  export interface Bot {
    AutoBuildBotLocales?: boolean;
    BotFileS3Location?: Bot.S3Location;
    BotLocales?: Bot.BotLocale[];
    BotTags?: Tag[];
    DataPrivacy: any;
    Description?: string;
    IdleSessionTTLInSeconds: number;
    Name: string;
    RoleArn: string;
    TestBotAliasSettings?: Bot.TestBotAliasSettings;
    TestBotAliasTags?: Tag[];
  }
  export namespace Bot {
    export interface Attr {
      Arn: string;
      Id: string;
    }
    export interface AdvancedRecognitionSetting {
      AudioRecognitionStrategy?: string;
    }
    export interface AllowedInputTypes {
      AllowAudioInput: boolean;
      AllowDTMFInput: boolean;
    }
    export interface AudioAndDTMFInputSpecification {
      AudioSpecification?: AudioSpecification;
      DTMFSpecification?: DTMFSpecification;
      StartTimeoutMs: number;
    }
    export interface AudioLogDestination {
      S3Bucket: S3BucketLogDestination;
    }
    export interface AudioLogSetting {
      Destination: AudioLogDestination;
      Enabled: boolean;
    }
    export interface AudioSpecification {
      EndTimeoutMs: number;
      MaxLengthMs: number;
    }
    export interface BotAliasLocaleSettings {
      CodeHookSpecification?: CodeHookSpecification;
      Enabled: boolean;
    }
    export interface BotAliasLocaleSettingsItem {
      BotAliasLocaleSetting: BotAliasLocaleSettings;
      LocaleId: string;
    }
    export interface BotLocale {
      CustomVocabulary?: CustomVocabulary;
      Description?: string;
      Intents?: Intent[];
      LocaleId: string;
      NluConfidenceThreshold: number;
      SlotTypes?: SlotType[];
      VoiceSettings?: VoiceSettings;
    }
    export interface Button {
      Text: string;
      Value: string;
    }
    export interface CloudWatchLogGroupLogDestination {
      CloudWatchLogGroupArn: string;
      LogPrefix: string;
    }
    export interface CodeHookSpecification {
      LambdaCodeHook: LambdaCodeHook;
    }
    export interface ConversationLogSettings {
      AudioLogSettings?: AudioLogSetting[];
      TextLogSettings?: TextLogSetting[];
    }
    export interface CustomPayload {
      Value: string;
    }
    export interface CustomVocabulary {
      CustomVocabularyItems: CustomVocabularyItem[];
    }
    export interface CustomVocabularyItem {
      Phrase: string;
      Weight?: number;
    }
    export interface DTMFSpecification {
      DeletionCharacter: string;
      EndCharacter: string;
      EndTimeoutMs: number;
      MaxLength: number;
    }
    export interface DataPrivacy {
      ChildDirected: boolean;
    }
    export interface DialogCodeHookSetting {
      Enabled: boolean;
    }
    export interface ExternalSourceSetting {
      GrammarSlotTypeSetting?: GrammarSlotTypeSetting;
    }
    export interface FulfillmentCodeHookSetting {
      Enabled: boolean;
      FulfillmentUpdatesSpecification?: FulfillmentUpdatesSpecification;
      PostFulfillmentStatusSpecification?: PostFulfillmentStatusSpecification;
    }
    export interface FulfillmentStartResponseSpecification {
      AllowInterrupt?: boolean;
      DelayInSeconds: number;
      MessageGroups: MessageGroup[];
    }
    export interface FulfillmentUpdateResponseSpecification {
      AllowInterrupt?: boolean;
      FrequencyInSeconds: number;
      MessageGroups: MessageGroup[];
    }
    export interface FulfillmentUpdatesSpecification {
      Active: boolean;
      StartResponse?: FulfillmentStartResponseSpecification;
      TimeoutInSeconds?: number;
      UpdateResponse?: FulfillmentUpdateResponseSpecification;
    }
    export interface GrammarSlotTypeSetting {
      Source?: GrammarSlotTypeSource;
    }
    export interface GrammarSlotTypeSource {
      KmsKeyArn?: string;
      S3BucketName: string;
      S3ObjectKey: string;
    }
    export interface ImageResponseCard {
      Buttons?: Button[];
      ImageUrl?: string;
      Subtitle?: string;
      Title: string;
    }
    export interface InputContext {
      Name: string;
    }
    export interface Intent {
      Description?: string;
      DialogCodeHook?: DialogCodeHookSetting;
      FulfillmentCodeHook?: FulfillmentCodeHookSetting;
      InputContexts?: InputContext[];
      IntentClosingSetting?: IntentClosingSetting;
      IntentConfirmationSetting?: IntentConfirmationSetting;
      KendraConfiguration?: KendraConfiguration;
      Name: string;
      OutputContexts?: OutputContext[];
      ParentIntentSignature?: string;
      SampleUtterances?: SampleUtterance[];
      SlotPriorities?: SlotPriority[];
      Slots?: Slot[];
    }
    export interface IntentClosingSetting {
      ClosingResponse: ResponseSpecification;
      IsActive?: boolean;
    }
    export interface IntentConfirmationSetting {
      DeclinationResponse: ResponseSpecification;
      IsActive?: boolean;
      PromptSpecification: PromptSpecification;
    }
    export interface KendraConfiguration {
      KendraIndex: string;
      QueryFilterString?: string;
      QueryFilterStringEnabled?: boolean;
    }
    export interface LambdaCodeHook {
      CodeHookInterfaceVersion: string;
      LambdaArn: string;
    }
    export interface Message {
      CustomPayload?: CustomPayload;
      ImageResponseCard?: ImageResponseCard;
      PlainTextMessage?: PlainTextMessage;
      SSMLMessage?: SSMLMessage;
    }
    export interface MessageGroup {
      Message: Message;
      Variations?: Message[];
    }
    export interface MultipleValuesSetting {
      AllowMultipleValues?: boolean;
    }
    export interface ObfuscationSetting {
      ObfuscationSettingType: string;
    }
    export interface OutputContext {
      Name: string;
      TimeToLiveInSeconds: number;
      TurnsToLive: number;
    }
    export interface PlainTextMessage {
      Value: string;
    }
    export interface PostFulfillmentStatusSpecification {
      FailureResponse?: ResponseSpecification;
      SuccessResponse?: ResponseSpecification;
      TimeoutResponse?: ResponseSpecification;
    }
    export interface PromptAttemptSpecification {
      AllowInterrupt?: boolean;
      AllowedInputTypes: AllowedInputTypes;
      AudioAndDTMFInputSpecification?: AudioAndDTMFInputSpecification;
      TextInputSpecification?: TextInputSpecification;
    }
    export interface PromptSpecification {
      AllowInterrupt?: boolean;
      MaxRetries: number;
      MessageGroupsList: MessageGroup[];
      MessageSelectionStrategy?: string;
      PromptAttemptsSpecification?: Record<string, PromptAttemptSpecification>;
    }
    export interface ResponseSpecification {
      AllowInterrupt?: boolean;
      MessageGroupsList: MessageGroup[];
    }
    export interface S3BucketLogDestination {
      KmsKeyArn?: string;
      LogPrefix: string;
      S3BucketArn: string;
    }
    export interface S3Location {
      S3Bucket: string;
      S3ObjectKey: string;
      S3ObjectVersion?: string;
    }
    export interface SSMLMessage {
      Value: string;
    }
    export interface SampleUtterance {
      Utterance: string;
    }
    export interface SampleValue {
      Value: string;
    }
    export interface SentimentAnalysisSettings {
      DetectSentiment: boolean;
    }
    export interface Slot {
      Description?: string;
      MultipleValuesSetting?: MultipleValuesSetting;
      Name: string;
      ObfuscationSetting?: ObfuscationSetting;
      SlotTypeName: string;
      ValueElicitationSetting: SlotValueElicitationSetting;
    }
    export interface SlotDefaultValue {
      DefaultValue: string;
    }
    export interface SlotDefaultValueSpecification {
      DefaultValueList: SlotDefaultValue[];
    }
    export interface SlotPriority {
      Priority: number;
      SlotName: string;
    }
    export interface SlotType {
      Description?: string;
      ExternalSourceSetting?: ExternalSourceSetting;
      Name: string;
      ParentSlotTypeSignature?: string;
      SlotTypeValues?: SlotTypeValue[];
      ValueSelectionSetting?: SlotValueSelectionSetting;
    }
    export interface SlotTypeValue {
      SampleValue: SampleValue;
      Synonyms?: SampleValue[];
    }
    export interface SlotValueElicitationSetting {
      DefaultValueSpecification?: SlotDefaultValueSpecification;
      PromptSpecification?: PromptSpecification;
      SampleUtterances?: SampleUtterance[];
      SlotConstraint: string;
      WaitAndContinueSpecification?: WaitAndContinueSpecification;
    }
    export interface SlotValueRegexFilter {
      Pattern: string;
    }
    export interface SlotValueSelectionSetting {
      AdvancedRecognitionSetting?: AdvancedRecognitionSetting;
      RegexFilter?: SlotValueRegexFilter;
      ResolutionStrategy: string;
    }
    export interface StillWaitingResponseSpecification {
      AllowInterrupt?: boolean;
      FrequencyInSeconds: number;
      MessageGroupsList: MessageGroup[];
      TimeoutInSeconds: number;
    }
    export interface TestBotAliasSettings {
      BotAliasLocaleSettings?: BotAliasLocaleSettingsItem[];
      ConversationLogSettings?: ConversationLogSettings;
      Description?: string;
      SentimentAnalysisSettings?: any;
    }
    export interface TextInputSpecification {
      StartTimeoutMs: number;
    }
    export interface TextLogDestination {
      CloudWatch: CloudWatchLogGroupLogDestination;
    }
    export interface TextLogSetting {
      Destination: TextLogDestination;
      Enabled: boolean;
    }
    export interface VoiceSettings {
      Engine?: string;
      VoiceId: string;
    }
    export interface WaitAndContinueSpecification {
      ContinueResponse: ResponseSpecification;
      IsActive?: boolean;
      StillWaitingResponse?: StillWaitingResponseSpecification;
      WaitingResponse: ResponseSpecification;
    }
  }
  export interface BotAlias {
    BotAliasLocaleSettings?: BotAlias.BotAliasLocaleSettingsItem[];
    BotAliasName: string;
    BotAliasTags?: Tag[];
    BotId: string;
    BotVersion?: string;
    ConversationLogSettings?: BotAlias.ConversationLogSettings;
    Description?: string;
    SentimentAnalysisSettings?: any;
  }
  export namespace BotAlias {
    export interface Attr {
      Arn: string;
      BotAliasId: string;
      BotAliasStatus: string;
    }
    export interface AudioLogDestination {
      S3Bucket: S3BucketLogDestination;
    }
    export interface AudioLogSetting {
      Destination: AudioLogDestination;
      Enabled: boolean;
    }
    export interface BotAliasLocaleSettings {
      CodeHookSpecification?: CodeHookSpecification;
      Enabled: boolean;
    }
    export interface BotAliasLocaleSettingsItem {
      BotAliasLocaleSetting: BotAliasLocaleSettings;
      LocaleId: string;
    }
    export interface CloudWatchLogGroupLogDestination {
      CloudWatchLogGroupArn: string;
      LogPrefix: string;
    }
    export interface CodeHookSpecification {
      LambdaCodeHook: LambdaCodeHook;
    }
    export interface ConversationLogSettings {
      AudioLogSettings?: AudioLogSetting[];
      TextLogSettings?: TextLogSetting[];
    }
    export interface LambdaCodeHook {
      CodeHookInterfaceVersion: string;
      LambdaArn: string;
    }
    export interface S3BucketLogDestination {
      KmsKeyArn?: string;
      LogPrefix: string;
      S3BucketArn: string;
    }
    export interface SentimentAnalysisSettings {
      DetectSentiment: boolean;
    }
    export interface TextLogDestination {
      CloudWatch: CloudWatchLogGroupLogDestination;
    }
    export interface TextLogSetting {
      Destination: TextLogDestination;
      Enabled: boolean;
    }
  }
  export interface BotVersion {
    BotId: string;
    BotVersionLocaleSpecification: BotVersion.BotVersionLocaleSpecification[];
    Description?: string;
  }
  export namespace BotVersion {
    export interface Attr {
      BotVersion: string;
    }
    export interface BotVersionLocaleDetails {
      SourceBotVersion: string;
    }
    export interface BotVersionLocaleSpecification {
      BotVersionLocaleDetails: BotVersionLocaleDetails;
      LocaleId: string;
    }
  }
  export interface ResourcePolicy {
    Policy: any;
    ResourceArn: string;
  }
}
export namespace LicenseManager {
  export interface Grant {
    AllowedOperations?: string[];
    GrantName?: string;
    HomeRegion?: string;
    LicenseArn?: string;
    Principals?: string[];
    Status?: string;
  }
  export interface License {
    Beneficiary?: string;
    ConsumptionConfiguration: License.ConsumptionConfiguration;
    Entitlements: License.Entitlement[];
    HomeRegion: string;
    Issuer: License.IssuerData;
    LicenseMetadata?: License.Metadata[];
    LicenseName: string;
    ProductName: string;
    ProductSKU?: string;
    Status?: string;
    Validity: License.ValidityDateFormat;
  }
  export namespace License {
    export interface Attr {
      LicenseArn: string;
      Version: string;
    }
    export interface BorrowConfiguration {
      AllowEarlyCheckIn: boolean;
      MaxTimeToLiveInMinutes: number;
    }
    export interface ConsumptionConfiguration {
      BorrowConfiguration?: BorrowConfiguration;
      ProvisionalConfiguration?: ProvisionalConfiguration;
      RenewType?: string;
    }
    export interface Entitlement {
      AllowCheckIn?: boolean;
      MaxCount?: number;
      Name: string;
      Overage?: boolean;
      Unit: string;
      Value?: string;
    }
    export interface IssuerData {
      Name: string;
      SignKey?: string;
    }
    export interface Metadata {
      Name: string;
      Value: string;
    }
    export interface ProvisionalConfiguration {
      MaxTimeToLiveInMinutes: number;
    }
    export interface ValidityDateFormat {
      Begin: string;
      End: string;
    }
  }
}
export namespace Lightsail {
  export interface Alarm {
    AlarmName: string;
    ComparisonOperator: string;
    ContactProtocols?: string[];
    DatapointsToAlarm?: number;
    EvaluationPeriods: number;
    MetricName: string;
    MonitoredResourceName: string;
    NotificationEnabled?: boolean;
    NotificationTriggers?: string[];
    Threshold: number;
    TreatMissingData?: string;
  }
  export interface Bucket {
    AccessRules?: Bucket.AccessRules;
    BucketName: string;
    BundleId: string;
    ObjectVersioning?: boolean;
    ReadOnlyAccessAccounts?: string[];
    ResourcesReceivingAccess?: string[];
    Tags?: Tag[];
  }
  export namespace Bucket {
    export interface Attr {
      AbleToUpdateBundle: boolean;
      BucketArn: string;
      Url: string;
    }
    export interface AccessRules {
      AllowPublicOverrides?: boolean;
      GetObject?: string;
    }
  }
  export interface Certificate {
    CertificateName: string;
    DomainName: string;
    SubjectAlternativeNames?: string[];
    Tags?: Tag[];
  }
  export interface Container {
    ContainerServiceDeployment?: Container.ContainerServiceDeployment;
    IsDisabled?: boolean;
    Power: string;
    PublicDomainNames?: Container.PublicDomainName[];
    Scale: number;
    ServiceName: string;
    Tags?: Tag[];
  }
  export namespace Container {
    export interface Attr {
      ContainerArn: string;
      Url: string;
    }
    export interface Container {
      Command?: string[];
      ContainerName?: string;
      Environment?: EnvironmentVariable[];
      Image?: string;
      Ports?: PortInfo[];
    }
    export interface ContainerServiceDeployment {
      Containers?: Container[];
      PublicEndpoint?: PublicEndpoint;
    }
    export interface EnvironmentVariable {
      Value?: string;
      Variable?: string;
    }
    export interface HealthCheckConfig {
      HealthyThreshold?: number;
      IntervalSeconds?: number;
      Path?: string;
      SuccessCodes?: string;
      TimeoutSeconds?: number;
      UnhealthyThreshold?: number;
    }
    export interface PortInfo {
      Port?: string;
      Protocol?: string;
    }
    export interface PublicDomainName {
      CertificateName?: string;
      DomainNames?: string[];
    }
    export interface PublicEndpoint {
      ContainerName?: string;
      ContainerPort?: number;
      HealthCheckConfig?: HealthCheckConfig;
    }
  }
  export interface Database {
    AvailabilityZone?: string;
    BackupRetention?: boolean;
    CaCertificateIdentifier?: string;
    MasterDatabaseName: string;
    MasterUserPassword?: string;
    MasterUsername: string;
    PreferredBackupWindow?: string;
    PreferredMaintenanceWindow?: string;
    PubliclyAccessible?: boolean;
    RelationalDatabaseBlueprintId: string;
    RelationalDatabaseBundleId: string;
    RelationalDatabaseName: string;
    RelationalDatabaseParameters?: Database.RelationalDatabaseParameter[];
    RotateMasterUserPassword?: boolean;
    Tags?: Tag[];
  }
  export namespace Database {
    export interface Attr {
      DatabaseArn: string;
    }
    export interface RelationalDatabaseParameter {
      AllowedValues?: string;
      ApplyMethod?: string;
      ApplyType?: string;
      DataType?: string;
      Description?: string;
      IsModifiable?: boolean;
      ParameterName?: string;
      ParameterValue?: string;
    }
  }
  export interface Disk {
    AddOns?: Disk.AddOn[];
    AvailabilityZone?: string;
    DiskName: string;
    SizeInGb: number;
    Tags?: Tag[];
  }
  export namespace Disk {
    export interface Attr {
      AttachedTo: string;
      AttachmentState: string;
      DiskArn: string;
      Iops: number;
      IsAttached: boolean;
      "Location.AvailabilityZone": string;
      "Location.RegionName": string;
      Path: string;
      ResourceType: string;
      State: string;
      SupportCode: string;
    }
    export interface AddOn {
      AddOnType: string;
      AutoSnapshotAddOnRequest?: AutoSnapshotAddOn;
      Status?: string;
    }
    export interface AutoSnapshotAddOn {
      SnapshotTimeOfDay?: string;
    }
    export interface Location {
      AvailabilityZone?: string;
      RegionName?: string;
    }
  }
  export interface Distribution {
    BundleId: string;
    CacheBehaviorSettings?: Distribution.CacheSettings;
    CacheBehaviors?: Distribution.CacheBehaviorPerPath[];
    CertificateName?: string;
    DefaultCacheBehavior: Distribution.CacheBehavior;
    DistributionName: string;
    IpAddressType?: string;
    IsEnabled?: boolean;
    Origin: Distribution.InputOrigin;
    Tags?: Tag[];
  }
  export namespace Distribution {
    export interface Attr {
      AbleToUpdateBundle: boolean;
      DistributionArn: string;
      Status: string;
    }
    export interface CacheBehavior {
      Behavior?: string;
    }
    export interface CacheBehaviorPerPath {
      Behavior?: string;
      Path?: string;
    }
    export interface CacheSettings {
      AllowedHTTPMethods?: string;
      CachedHTTPMethods?: string;
      DefaultTTL?: number;
      ForwardedCookies?: CookieObject;
      ForwardedHeaders?: HeaderObject;
      ForwardedQueryStrings?: QueryStringObject;
      MaximumTTL?: number;
      MinimumTTL?: number;
    }
    export interface CookieObject {
      CookiesAllowList?: string[];
      Option?: string;
    }
    export interface HeaderObject {
      HeadersAllowList?: string[];
      Option?: string;
    }
    export interface InputOrigin {
      Name?: string;
      ProtocolPolicy?: string;
      RegionName?: string;
    }
    export interface QueryStringObject {
      Option?: boolean;
      QueryStringsAllowList?: string[];
    }
  }
  export interface Instance {
    AddOns?: Instance.AddOn[];
    AvailabilityZone?: string;
    BlueprintId: string;
    BundleId: string;
    Hardware?: Instance.Hardware;
    InstanceName: string;
    KeyPairName?: string;
    Location?: Instance.Location;
    Networking?: Instance.Networking;
    State?: Instance.State;
    Tags?: Tag[];
    UserData?: string;
  }
  export namespace Instance {
    export interface Attr {
      "Hardware.CpuCount": number;
      "Hardware.RamSizeInGb": number;
      InstanceArn: string;
      IsStaticIp: boolean;
      "Location.AvailabilityZone": string;
      "Location.RegionName": string;
      "Networking.MonthlyTransfer.GbPerMonthAllocated": string;
      PrivateIpAddress: string;
      PublicIpAddress: string;
      ResourceType: string;
      SshKeyName: string;
      "State.Code": number;
      "State.Name": string;
      SupportCode: string;
      UserName: string;
    }
    export interface AddOn {
      AddOnType: string;
      AutoSnapshotAddOnRequest?: AutoSnapshotAddOn;
      Status?: string;
    }
    export interface AutoSnapshotAddOn {
      SnapshotTimeOfDay?: string;
    }
    export interface Disk {
      AttachedTo?: string;
      AttachmentState?: string;
      DiskName: string;
      IOPS?: number;
      IsSystemDisk?: boolean;
      Path: string;
      SizeInGb?: string;
    }
    export interface Hardware {
      CpuCount?: number;
      Disks?: Disk[];
      RamSizeInGb?: number;
    }
    export interface Location {
      AvailabilityZone?: string;
      RegionName?: string;
    }
    export interface MonthlyTransfer {
      GbPerMonthAllocated?: string;
    }
    export interface Networking {
      MonthlyTransfer?: number;
      Ports: Port[];
    }
    export interface Port {
      AccessDirection?: string;
      AccessFrom?: string;
      AccessType?: string;
      CidrListAliases?: string[];
      Cidrs?: string[];
      CommonName?: string;
      FromPort?: number;
      Ipv6Cidrs?: string[];
      Protocol?: string;
      ToPort?: number;
    }
    export interface State {
      Code?: number;
      Name?: string;
    }
  }
  export interface LoadBalancer {
    AttachedInstances?: string[];
    HealthCheckPath?: string;
    InstancePort: number;
    IpAddressType?: string;
    LoadBalancerName: string;
    SessionStickinessEnabled?: boolean;
    SessionStickinessLBCookieDurationSeconds?: string;
    Tags?: Tag[];
    TlsPolicyName?: string;
  }
  export interface LoadBalancerTlsCertificate {
    CertificateAlternativeNames?: string[];
    CertificateDomainName: string;
    CertificateName: string;
    HttpsRedirectionEnabled?: boolean;
    IsAttached?: boolean;
    LoadBalancerName: string;
  }
  export interface StaticIp {
    AttachedTo?: string;
    StaticIpName: string;
  }
}
export namespace Location {
  export interface GeofenceCollection {
    CollectionName: string;
    Description?: string;
    KmsKeyId?: string;
    PricingPlan?: string;
    PricingPlanDataSource?: string;
  }
  export interface Map {
    Configuration: Map.MapConfiguration;
    Description?: string;
    MapName: string;
    PricingPlan?: string;
  }
  export namespace Map {
    export interface Attr {
      Arn: string;
      CreateTime: string;
      DataSource: string;
      MapArn: string;
      UpdateTime: string;
    }
    export interface MapConfiguration {
      Style: string;
    }
  }
  export interface PlaceIndex {
    DataSource: string;
    DataSourceConfiguration?: PlaceIndex.DataSourceConfiguration;
    Description?: string;
    IndexName: string;
    PricingPlan?: string;
  }
  export namespace PlaceIndex {
    export interface Attr {
      Arn: string;
      CreateTime: string;
      IndexArn: string;
      UpdateTime: string;
    }
    export interface DataSourceConfiguration {
      IntendedUse?: string;
    }
  }
  export interface RouteCalculator {
    CalculatorName: string;
    DataSource: string;
    Description?: string;
    PricingPlan?: string;
  }
  export interface Tracker {
    Description?: string;
    KmsKeyId?: string;
    PositionFiltering?: string;
    PricingPlan?: string;
    PricingPlanDataSource?: string;
    TrackerName: string;
  }
  export interface TrackerConsumer {
    ConsumerArn: string;
    TrackerName: string;
  }
}
export namespace Logs {
  export interface Destination {
    DestinationName: string;
    DestinationPolicy?: string;
    RoleArn: string;
    TargetArn: string;
  }
  export interface LogGroup {
    DataProtectionPolicy?: any;
    KmsKeyId?: string;
    LogGroupName?: string;
    RetentionInDays?: number;
    Tags?: Tag[];
  }
  export interface LogStream {
    LogGroupName: string;
    LogStreamName?: string;
  }
  export interface MetricFilter {
    FilterName?: string;
    FilterPattern: string;
    LogGroupName: string;
    MetricTransformations: MetricFilter.MetricTransformation[];
  }
  export namespace MetricFilter {
    export interface Attr {}
    export interface Dimension {
      Key: string;
      Value: string;
    }
    export interface MetricTransformation {
      DefaultValue?: number;
      Dimensions?: Dimension[];
      MetricName: string;
      MetricNamespace: string;
      MetricValue: string;
      Unit?: string;
    }
  }
  export interface QueryDefinition {
    LogGroupNames?: string[];
    Name: string;
    QueryString: string;
  }
  export interface ResourcePolicy {
    PolicyDocument: string;
    PolicyName: string;
  }
  export interface SubscriptionFilter {
    DestinationArn: string;
    Distribution?: string;
    FilterName?: string;
    FilterPattern: string;
    LogGroupName: string;
    RoleArn?: string;
  }
}
export namespace LookoutEquipment {
  export interface InferenceScheduler {
    DataDelayOffsetInMinutes?: number;
    DataInputConfiguration: any;
    DataOutputConfiguration: any;
    DataUploadFrequency: string;
    InferenceSchedulerName?: string;
    ModelName: string;
    RoleArn: string;
    ServerSideKmsKeyId?: string;
    Tags?: Tag[];
  }
  export namespace InferenceScheduler {
    export interface Attr {
      InferenceSchedulerArn: string;
    }
    export interface DataInputConfiguration {
      InferenceInputNameConfiguration?: InputNameConfiguration;
      InputTimeZoneOffset?: string;
      S3InputConfiguration: S3InputConfiguration;
    }
    export interface DataOutputConfiguration {
      KmsKeyId?: string;
      S3OutputConfiguration: S3OutputConfiguration;
    }
    export interface InputNameConfiguration {
      ComponentTimestampDelimiter?: string;
      TimestampFormat?: string;
    }
    export interface S3InputConfiguration {
      Bucket: string;
      Prefix?: string;
    }
    export interface S3OutputConfiguration {
      Bucket: string;
      Prefix?: string;
    }
  }
}
export namespace LookoutMetrics {
  export interface Alert {
    Action: Alert.Action;
    AlertDescription?: string;
    AlertName?: string;
    AlertSensitivityThreshold: number;
    AnomalyDetectorArn: string;
  }
  export namespace Alert {
    export interface Attr {
      Arn: string;
    }
    export interface Action {
      LambdaConfiguration?: LambdaConfiguration;
      SNSConfiguration?: SNSConfiguration;
    }
    export interface LambdaConfiguration {
      LambdaArn: string;
      RoleArn: string;
    }
    export interface SNSConfiguration {
      RoleArn: string;
      SnsTopicArn: string;
    }
  }
  export interface AnomalyDetector {
    AnomalyDetectorConfig: AnomalyDetector.AnomalyDetectorConfig;
    AnomalyDetectorDescription?: string;
    AnomalyDetectorName?: string;
    KmsKeyArn?: string;
    MetricSetList: AnomalyDetector.MetricSet[];
  }
  export namespace AnomalyDetector {
    export interface Attr {
      Arn: string;
    }
    export interface AnomalyDetectorConfig {
      AnomalyDetectorFrequency: string;
    }
    export interface AppFlowConfig {
      FlowName: string;
      RoleArn: string;
    }
    export interface CloudwatchConfig {
      RoleArn: string;
    }
    export interface CsvFormatDescriptor {
      Charset?: string;
      ContainsHeader?: boolean;
      Delimiter?: string;
      FileCompression?: string;
      HeaderList?: string[];
      QuoteSymbol?: string;
    }
    export interface FileFormatDescriptor {
      CsvFormatDescriptor?: CsvFormatDescriptor;
      JsonFormatDescriptor?: JsonFormatDescriptor;
    }
    export interface JsonFormatDescriptor {
      Charset?: string;
      FileCompression?: string;
    }
    export interface Metric {
      AggregationFunction: string;
      MetricName: string;
      Namespace?: string;
    }
    export interface MetricSet {
      DimensionList?: string[];
      MetricList: Metric[];
      MetricSetDescription?: string;
      MetricSetFrequency?: string;
      MetricSetName: string;
      MetricSource: MetricSource;
      Offset?: number;
      TimestampColumn?: TimestampColumn;
      Timezone?: string;
    }
    export interface MetricSource {
      AppFlowConfig?: AppFlowConfig;
      CloudwatchConfig?: CloudwatchConfig;
      RDSSourceConfig?: RDSSourceConfig;
      RedshiftSourceConfig?: RedshiftSourceConfig;
      S3SourceConfig?: S3SourceConfig;
    }
    export interface RDSSourceConfig {
      DBInstanceIdentifier: string;
      DatabaseHost: string;
      DatabaseName: string;
      DatabasePort: number;
      RoleArn: string;
      SecretManagerArn: string;
      TableName: string;
      VpcConfiguration: VpcConfiguration;
    }
    export interface RedshiftSourceConfig {
      ClusterIdentifier: string;
      DatabaseHost: string;
      DatabaseName: string;
      DatabasePort: number;
      RoleArn: string;
      SecretManagerArn: string;
      TableName: string;
      VpcConfiguration: VpcConfiguration;
    }
    export interface S3SourceConfig {
      FileFormatDescriptor: FileFormatDescriptor;
      HistoricalDataPathList?: string[];
      RoleArn: string;
      TemplatedPathList?: string[];
    }
    export interface TimestampColumn {
      ColumnFormat?: string;
      ColumnName?: string;
    }
    export interface VpcConfiguration {
      SecurityGroupIdList: string[];
      SubnetIdList: string[];
    }
  }
}
export namespace LookoutVision {
  export interface Project {
    ProjectName: string;
  }
}
export namespace M2 {
  export interface Application {
    Definition: Application.Definition;
    Description?: string;
    EngineType: string;
    KmsKeyId?: string;
    Name: string;
    Tags?: Record<string, string>;
  }
  export namespace Application {
    export interface Attr {
      ApplicationArn: string;
      ApplicationId: string;
    }
    export interface Definition {
      Content?: string;
      S3Location?: string;
    }
  }
  export interface Environment {
    Description?: string;
    EngineType: string;
    EngineVersion?: string;
    HighAvailabilityConfig?: Environment.HighAvailabilityConfig;
    InstanceType: string;
    KmsKeyId?: string;
    Name: string;
    PreferredMaintenanceWindow?: string;
    PubliclyAccessible?: boolean;
    SecurityGroupIds?: string[];
    StorageConfigurations?: Environment.StorageConfiguration[];
    SubnetIds?: string[];
    Tags?: Record<string, string>;
  }
  export namespace Environment {
    export interface Attr {
      EnvironmentArn: string;
      EnvironmentId: string;
    }
    export interface EfsStorageConfiguration {
      FileSystemId: string;
      MountPoint: string;
    }
    export interface FsxStorageConfiguration {
      FileSystemId: string;
      MountPoint: string;
    }
    export interface HighAvailabilityConfig {
      DesiredCapacity: number;
    }
    export interface StorageConfiguration {
      Efs?: EfsStorageConfiguration;
      Fsx?: FsxStorageConfiguration;
    }
  }
}
export namespace MSK {
  export interface BatchScramSecret {
    ClusterArn: string;
    SecretArnList?: string[];
  }
  export interface Cluster {
    BrokerNodeGroupInfo: Cluster.BrokerNodeGroupInfo;
    ClientAuthentication?: Cluster.ClientAuthentication;
    ClusterName: string;
    ConfigurationInfo?: Cluster.ConfigurationInfo;
    CurrentVersion?: string;
    EncryptionInfo?: Cluster.EncryptionInfo;
    EnhancedMonitoring?: string;
    KafkaVersion: string;
    LoggingInfo?: Cluster.LoggingInfo;
    NumberOfBrokerNodes: number;
    OpenMonitoring?: Cluster.OpenMonitoring;
    StorageMode?: string;
    Tags?: Record<string, string>;
  }
  export namespace Cluster {
    export interface Attr {
      Arn: string;
    }
    export interface BrokerLogs {
      CloudWatchLogs?: CloudWatchLogs;
      Firehose?: Firehose;
      S3?: S3;
    }
    export interface BrokerNodeGroupInfo {
      BrokerAZDistribution?: string;
      ClientSubnets: string[];
      ConnectivityInfo?: ConnectivityInfo;
      InstanceType: string;
      SecurityGroups?: string[];
      StorageInfo?: StorageInfo;
    }
    export interface ClientAuthentication {
      Sasl?: Sasl;
      Tls?: Tls;
      Unauthenticated?: Unauthenticated;
    }
    export interface CloudWatchLogs {
      Enabled: boolean;
      LogGroup?: string;
    }
    export interface ConfigurationInfo {
      Arn: string;
      Revision: number;
    }
    export interface ConnectivityInfo {
      PublicAccess?: PublicAccess;
      VpcConnectivity?: VpcConnectivity;
    }
    export interface EBSStorageInfo {
      ProvisionedThroughput?: ProvisionedThroughput;
      VolumeSize?: number;
    }
    export interface EncryptionAtRest {
      DataVolumeKMSKeyId: string;
    }
    export interface EncryptionInTransit {
      ClientBroker?: string;
      InCluster?: boolean;
    }
    export interface EncryptionInfo {
      EncryptionAtRest?: EncryptionAtRest;
      EncryptionInTransit?: EncryptionInTransit;
    }
    export interface Firehose {
      DeliveryStream?: string;
      Enabled: boolean;
    }
    export interface Iam {
      Enabled: boolean;
    }
    export interface JmxExporter {
      EnabledInBroker: boolean;
    }
    export interface LoggingInfo {
      BrokerLogs: BrokerLogs;
    }
    export interface NodeExporter {
      EnabledInBroker: boolean;
    }
    export interface OpenMonitoring {
      Prometheus: Prometheus;
    }
    export interface Prometheus {
      JmxExporter?: JmxExporter;
      NodeExporter?: NodeExporter;
    }
    export interface ProvisionedThroughput {
      Enabled?: boolean;
      VolumeThroughput?: number;
    }
    export interface PublicAccess {
      Type?: string;
    }
    export interface S3 {
      Bucket?: string;
      Enabled: boolean;
      Prefix?: string;
    }
    export interface Sasl {
      Iam?: Iam;
      Scram?: Scram;
    }
    export interface Scram {
      Enabled: boolean;
    }
    export interface StorageInfo {
      EBSStorageInfo?: EBSStorageInfo;
    }
    export interface Tls {
      CertificateAuthorityArnList?: string[];
      Enabled?: boolean;
    }
    export interface Unauthenticated {
      Enabled: boolean;
    }
    export interface VpcConnectivity {
      ClientAuthentication?: VpcConnectivityClientAuthentication;
    }
    export interface VpcConnectivityClientAuthentication {
      Sasl?: VpcConnectivitySasl;
      Tls?: VpcConnectivityTls;
    }
    export interface VpcConnectivityIam {
      Enabled: boolean;
    }
    export interface VpcConnectivitySasl {
      Iam?: VpcConnectivityIam;
      Scram?: VpcConnectivityScram;
    }
    export interface VpcConnectivityScram {
      Enabled: boolean;
    }
    export interface VpcConnectivityTls {
      Enabled: boolean;
    }
  }
  export interface Configuration {
    Description?: string;
    KafkaVersionsList?: string[];
    Name: string;
    ServerProperties: string;
  }
  export interface ServerlessCluster {
    ClientAuthentication: ServerlessCluster.ClientAuthentication;
    ClusterName: string;
    Tags?: Record<string, string>;
    VpcConfigs: ServerlessCluster.VpcConfig[];
  }
  export namespace ServerlessCluster {
    export interface Attr {
      Arn: string;
    }
    export interface ClientAuthentication {
      Sasl: Sasl;
    }
    export interface Iam {
      Enabled: boolean;
    }
    export interface Sasl {
      Iam: Iam;
    }
    export interface VpcConfig {
      SecurityGroups?: string[];
      SubnetIds: string[];
    }
  }
}
export namespace MWAA {
  export interface Environment {
    AirflowConfigurationOptions?: any;
    AirflowVersion?: string;
    DagS3Path?: string;
    EnvironmentClass?: string;
    ExecutionRoleArn?: string;
    KmsKey?: string;
    LoggingConfiguration?: Environment.LoggingConfiguration;
    MaxWorkers?: number;
    MinWorkers?: number;
    Name: string;
    NetworkConfiguration?: Environment.NetworkConfiguration;
    PluginsS3ObjectVersion?: string;
    PluginsS3Path?: string;
    RequirementsS3ObjectVersion?: string;
    RequirementsS3Path?: string;
    Schedulers?: number;
    SourceBucketArn?: string;
    Tags?: any;
    WebserverAccessMode?: string;
    WeeklyMaintenanceWindowStart?: string;
  }
  export namespace Environment {
    export interface Attr {
      Arn: string;
      "LoggingConfiguration.DagProcessingLogs.CloudWatchLogGroupArn": string;
      "LoggingConfiguration.SchedulerLogs.CloudWatchLogGroupArn": string;
      "LoggingConfiguration.TaskLogs.CloudWatchLogGroupArn": string;
      "LoggingConfiguration.WebserverLogs.CloudWatchLogGroupArn": string;
      "LoggingConfiguration.WorkerLogs.CloudWatchLogGroupArn": string;
      WebserverUrl: string;
    }
    export interface LoggingConfiguration {
      DagProcessingLogs?: ModuleLoggingConfiguration;
      SchedulerLogs?: ModuleLoggingConfiguration;
      TaskLogs?: ModuleLoggingConfiguration;
      WebserverLogs?: ModuleLoggingConfiguration;
      WorkerLogs?: ModuleLoggingConfiguration;
    }
    export interface ModuleLoggingConfiguration {
      CloudWatchLogGroupArn?: string;
      Enabled?: boolean;
      LogLevel?: string;
    }
    export interface NetworkConfiguration {
      SecurityGroupIds?: string[];
      SubnetIds?: string[];
    }
  }
}
export namespace Macie {
  export interface AllowList {
    Criteria: AllowList.Criteria;
    Description?: string;
    Name: string;
    Tags?: Tag[];
  }
  export namespace AllowList {
    export interface Attr {
      Arn: string;
      Id: string;
      Status: string;
    }
    export interface Criteria {
      Regex?: string;
      S3WordsList?: S3WordsList;
    }
    export interface S3WordsList {
      BucketName: string;
      ObjectKey: string;
    }
  }
  export interface CustomDataIdentifier {
    Description?: string;
    IgnoreWords?: string[];
    Keywords?: string[];
    MaximumMatchDistance?: number;
    Name: string;
    Regex: string;
  }
  export interface FindingsFilter {
    Action?: string;
    Description?: string;
    FindingCriteria: FindingsFilter.FindingCriteria;
    Name: string;
    Position?: number;
  }
  export namespace FindingsFilter {
    export interface Attr {
      Arn: string;
      FindingsFilterListItems: any[];
      Id: string;
    }
    export interface CriterionAdditionalProperties {
      eq?: string[];
      gt?: number;
      gte?: number;
      lt?: number;
      lte?: number;
      neq?: string[];
    }
    export interface FindingCriteria {
      Criterion?: Record<string, CriterionAdditionalProperties>;
    }
    export interface FindingsFilterListItem {
      Id?: string;
      Name?: string;
    }
  }
  export interface Session {
    FindingPublishingFrequency?: string;
    Status?: string;
  }
}
export namespace ManagedBlockchain {
  export interface Member {
    InvitationId?: string;
    MemberConfiguration: Member.MemberConfiguration;
    NetworkConfiguration?: Member.NetworkConfiguration;
    NetworkId?: string;
  }
  export namespace Member {
    export interface Attr {
      MemberId: string;
      NetworkId: string;
    }
    export interface ApprovalThresholdPolicy {
      ProposalDurationInHours?: number;
      ThresholdComparator?: string;
      ThresholdPercentage?: number;
    }
    export interface MemberConfiguration {
      Description?: string;
      MemberFrameworkConfiguration?: MemberFrameworkConfiguration;
      Name: string;
    }
    export interface MemberFabricConfiguration {
      AdminPassword: string;
      AdminUsername: string;
    }
    export interface MemberFrameworkConfiguration {
      MemberFabricConfiguration?: MemberFabricConfiguration;
    }
    export interface NetworkConfiguration {
      Description?: string;
      Framework: string;
      FrameworkVersion: string;
      Name: string;
      NetworkFrameworkConfiguration?: NetworkFrameworkConfiguration;
      VotingPolicy: VotingPolicy;
    }
    export interface NetworkFabricConfiguration {
      Edition: string;
    }
    export interface NetworkFrameworkConfiguration {
      NetworkFabricConfiguration?: NetworkFabricConfiguration;
    }
    export interface VotingPolicy {
      ApprovalThresholdPolicy?: ApprovalThresholdPolicy;
    }
  }
  export interface Node {
    MemberId?: string;
    NetworkId: string;
    NodeConfiguration: Node.NodeConfiguration;
  }
  export namespace Node {
    export interface Attr {
      Arn: string;
      MemberId: string;
      NetworkId: string;
      NodeId: string;
    }
    export interface NodeConfiguration {
      AvailabilityZone: string;
      InstanceType: string;
    }
  }
}
export namespace MediaConnect {
  export interface Flow {
    AvailabilityZone?: string;
    Name: string;
    Source: Flow.Source;
    SourceFailoverConfig?: Flow.FailoverConfig;
  }
  export namespace Flow {
    export interface Attr {
      FlowArn: string;
      FlowAvailabilityZone: string;
      "Source.IngestIp": string;
      "Source.SourceArn": string;
      "Source.SourceIngestPort": string;
    }
    export interface Encryption {
      Algorithm?: string;
      ConstantInitializationVector?: string;
      DeviceId?: string;
      KeyType?: string;
      Region?: string;
      ResourceId?: string;
      RoleArn: string;
      SecretArn?: string;
      Url?: string;
    }
    export interface FailoverConfig {
      FailoverMode?: string;
      RecoveryWindow?: number;
      SourcePriority?: SourcePriority;
      State?: string;
    }
    export interface Source {
      Decryption?: Encryption;
      Description?: string;
      EntitlementArn?: string;
      IngestIp?: string;
      IngestPort?: number;
      MaxBitrate?: number;
      MaxLatency?: number;
      MinLatency?: number;
      Name?: string;
      Protocol?: string;
      SenderControlPort?: number;
      SenderIpAddress?: string;
      SourceArn?: string;
      SourceIngestPort?: string;
      SourceListenerAddress?: string;
      SourceListenerPort?: number;
      StreamId?: string;
      VpcInterfaceName?: string;
      WhitelistCidr?: string;
    }
    export interface SourcePriority {
      PrimarySource: string;
    }
  }
  export interface FlowEntitlement {
    DataTransferSubscriberFeePercent?: number;
    Description: string;
    Encryption?: FlowEntitlement.Encryption;
    EntitlementStatus?: string;
    FlowArn: string;
    Name: string;
    Subscribers: string[];
  }
  export namespace FlowEntitlement {
    export interface Attr {
      EntitlementArn: string;
    }
    export interface Encryption {
      Algorithm: string;
      ConstantInitializationVector?: string;
      DeviceId?: string;
      KeyType?: string;
      Region?: string;
      ResourceId?: string;
      RoleArn: string;
      SecretArn?: string;
      Url?: string;
    }
  }
  export interface FlowOutput {
    CidrAllowList?: string[];
    Description?: string;
    Destination?: string;
    Encryption?: FlowOutput.Encryption;
    FlowArn: string;
    MaxLatency?: number;
    MinLatency?: number;
    Name?: string;
    Port?: number;
    Protocol: string;
    RemoteId?: string;
    SmoothingLatency?: number;
    StreamId?: string;
    VpcInterfaceAttachment?: FlowOutput.VpcInterfaceAttachment;
  }
  export namespace FlowOutput {
    export interface Attr {
      OutputArn: string;
    }
    export interface Encryption {
      Algorithm?: string;
      KeyType?: string;
      RoleArn: string;
      SecretArn: string;
    }
    export interface VpcInterfaceAttachment {
      VpcInterfaceName?: string;
    }
  }
  export interface FlowSource {
    Decryption?: FlowSource.Encryption;
    Description: string;
    EntitlementArn?: string;
    FlowArn?: string;
    IngestPort?: number;
    MaxBitrate?: number;
    MaxLatency?: number;
    Name: string;
    Protocol?: string;
    StreamId?: string;
    VpcInterfaceName?: string;
    WhitelistCidr?: string;
  }
  export namespace FlowSource {
    export interface Attr {
      IngestIp: string;
      SourceArn: string;
      SourceIngestPort: string;
    }
    export interface Encryption {
      Algorithm: string;
      ConstantInitializationVector?: string;
      DeviceId?: string;
      KeyType?: string;
      Region?: string;
      ResourceId?: string;
      RoleArn: string;
      SecretArn?: string;
      Url?: string;
    }
  }
  export interface FlowVpcInterface {
    FlowArn: string;
    Name: string;
    RoleArn: string;
    SecurityGroupIds: string[];
    SubnetId: string;
  }
}
export namespace MediaConvert {
  export interface JobTemplate {
    AccelerationSettings?: JobTemplate.AccelerationSettings;
    Category?: string;
    Description?: string;
    HopDestinations?: JobTemplate.HopDestination[];
    Name?: string;
    Priority?: number;
    Queue?: string;
    SettingsJson: any;
    StatusUpdateInterval?: string;
    Tags?: any;
  }
  export namespace JobTemplate {
    export interface Attr {
      Arn: string;
      Name: string;
    }
    export interface AccelerationSettings {
      Mode: string;
    }
    export interface HopDestination {
      Priority?: number;
      Queue?: string;
      WaitMinutes?: number;
    }
  }
  export interface Preset {
    Category?: string;
    Description?: string;
    Name?: string;
    SettingsJson: any;
    Tags?: any;
  }
  export interface Queue {
    Description?: string;
    Name?: string;
    PricingPlan?: string;
    Status?: string;
    Tags?: any;
  }
}
export namespace MediaLive {
  export interface Channel {
    CdiInputSpecification?: Channel.CdiInputSpecification;
    ChannelClass?: string;
    Destinations?: Channel.OutputDestination[];
    EncoderSettings?: Channel.EncoderSettings;
    InputAttachments?: Channel.InputAttachment[];
    InputSpecification?: Channel.InputSpecification;
    LogLevel?: string;
    Name?: string;
    RoleArn?: string;
    Tags?: any;
    Vpc?: Channel.VpcOutputSettings;
  }
  export namespace Channel {
    export interface Attr {
      Arn: string;
      Inputs: string[];
    }
    export interface AacSettings {
      Bitrate?: number;
      CodingMode?: string;
      InputType?: string;
      Profile?: string;
      RateControlMode?: string;
      RawFormat?: string;
      SampleRate?: number;
      Spec?: string;
      VbrQuality?: string;
    }
    export interface Ac3Settings {
      Bitrate?: number;
      BitstreamMode?: string;
      CodingMode?: string;
      Dialnorm?: number;
      DrcProfile?: string;
      LfeFilter?: string;
      MetadataControl?: string;
    }
    export interface AncillarySourceSettings {
      SourceAncillaryChannelNumber?: number;
    }
    export interface ArchiveCdnSettings {
      ArchiveS3Settings?: ArchiveS3Settings;
    }
    export interface ArchiveContainerSettings {
      M2tsSettings?: M2tsSettings;
      RawSettings?: RawSettings;
    }
    export interface ArchiveGroupSettings {
      ArchiveCdnSettings?: ArchiveCdnSettings;
      Destination?: OutputLocationRef;
      RolloverInterval?: number;
    }
    export interface ArchiveOutputSettings {
      ContainerSettings?: ArchiveContainerSettings;
      Extension?: string;
      NameModifier?: string;
    }
    export interface ArchiveS3Settings {
      CannedAcl?: string;
    }
    export interface AribDestinationSettings {}
    export interface AribSourceSettings {}
    export interface AudioChannelMapping {
      InputChannelLevels?: InputChannelLevel[];
      OutputChannel?: number;
    }
    export interface AudioCodecSettings {
      AacSettings?: AacSettings;
      Ac3Settings?: Ac3Settings;
      Eac3Settings?: Eac3Settings;
      Mp2Settings?: Mp2Settings;
      PassThroughSettings?: PassThroughSettings;
      WavSettings?: WavSettings;
    }
    export interface AudioDescription {
      AudioNormalizationSettings?: AudioNormalizationSettings;
      AudioSelectorName?: string;
      AudioType?: string;
      AudioTypeControl?: string;
      AudioWatermarkingSettings?: AudioWatermarkSettings;
      CodecSettings?: AudioCodecSettings;
      LanguageCode?: string;
      LanguageCodeControl?: string;
      Name?: string;
      RemixSettings?: RemixSettings;
      StreamName?: string;
    }
    export interface AudioHlsRenditionSelection {
      GroupId?: string;
      Name?: string;
    }
    export interface AudioLanguageSelection {
      LanguageCode?: string;
      LanguageSelectionPolicy?: string;
    }
    export interface AudioNormalizationSettings {
      Algorithm?: string;
      AlgorithmControl?: string;
      TargetLkfs?: number;
    }
    export interface AudioOnlyHlsSettings {
      AudioGroupId?: string;
      AudioOnlyImage?: InputLocation;
      AudioTrackType?: string;
      SegmentType?: string;
    }
    export interface AudioPidSelection {
      Pid?: number;
    }
    export interface AudioSelector {
      Name?: string;
      SelectorSettings?: AudioSelectorSettings;
    }
    export interface AudioSelectorSettings {
      AudioHlsRenditionSelection?: AudioHlsRenditionSelection;
      AudioLanguageSelection?: AudioLanguageSelection;
      AudioPidSelection?: AudioPidSelection;
      AudioTrackSelection?: AudioTrackSelection;
    }
    export interface AudioSilenceFailoverSettings {
      AudioSelectorName?: string;
      AudioSilenceThresholdMsec?: number;
    }
    export interface AudioTrack {
      Track?: number;
    }
    export interface AudioTrackSelection {
      Tracks?: AudioTrack[];
    }
    export interface AudioWatermarkSettings {
      NielsenWatermarksSettings?: NielsenWatermarksSettings;
    }
    export interface AutomaticInputFailoverSettings {
      ErrorClearTimeMsec?: number;
      FailoverConditions?: FailoverCondition[];
      InputPreference?: string;
      SecondaryInputId?: string;
    }
    export interface AvailBlanking {
      AvailBlankingImage?: InputLocation;
      State?: string;
    }
    export interface AvailConfiguration {
      AvailSettings?: AvailSettings;
    }
    export interface AvailSettings {
      Scte35SpliceInsert?: Scte35SpliceInsert;
      Scte35TimeSignalApos?: Scte35TimeSignalApos;
    }
    export interface BlackoutSlate {
      BlackoutSlateImage?: InputLocation;
      NetworkEndBlackout?: string;
      NetworkEndBlackoutImage?: InputLocation;
      NetworkId?: string;
      State?: string;
    }
    export interface BurnInDestinationSettings {
      Alignment?: string;
      BackgroundColor?: string;
      BackgroundOpacity?: number;
      Font?: InputLocation;
      FontColor?: string;
      FontOpacity?: number;
      FontResolution?: number;
      FontSize?: string;
      OutlineColor?: string;
      OutlineSize?: number;
      ShadowColor?: string;
      ShadowOpacity?: number;
      ShadowXOffset?: number;
      ShadowYOffset?: number;
      TeletextGridControl?: string;
      XPosition?: number;
      YPosition?: number;
    }
    export interface CaptionDescription {
      CaptionSelectorName?: string;
      DestinationSettings?: CaptionDestinationSettings;
      LanguageCode?: string;
      LanguageDescription?: string;
      Name?: string;
    }
    export interface CaptionDestinationSettings {
      AribDestinationSettings?: AribDestinationSettings;
      BurnInDestinationSettings?: BurnInDestinationSettings;
      DvbSubDestinationSettings?: DvbSubDestinationSettings;
      EbuTtDDestinationSettings?: EbuTtDDestinationSettings;
      EmbeddedDestinationSettings?: EmbeddedDestinationSettings;
      EmbeddedPlusScte20DestinationSettings?: EmbeddedPlusScte20DestinationSettings;
      RtmpCaptionInfoDestinationSettings?: RtmpCaptionInfoDestinationSettings;
      Scte20PlusEmbeddedDestinationSettings?: Scte20PlusEmbeddedDestinationSettings;
      Scte27DestinationSettings?: Scte27DestinationSettings;
      SmpteTtDestinationSettings?: SmpteTtDestinationSettings;
      TeletextDestinationSettings?: TeletextDestinationSettings;
      TtmlDestinationSettings?: TtmlDestinationSettings;
      WebvttDestinationSettings?: WebvttDestinationSettings;
    }
    export interface CaptionLanguageMapping {
      CaptionChannel?: number;
      LanguageCode?: string;
      LanguageDescription?: string;
    }
    export interface CaptionRectangle {
      Height?: number;
      LeftOffset?: number;
      TopOffset?: number;
      Width?: number;
    }
    export interface CaptionSelector {
      LanguageCode?: string;
      Name?: string;
      SelectorSettings?: CaptionSelectorSettings;
    }
    export interface CaptionSelectorSettings {
      AncillarySourceSettings?: AncillarySourceSettings;
      AribSourceSettings?: AribSourceSettings;
      DvbSubSourceSettings?: DvbSubSourceSettings;
      EmbeddedSourceSettings?: EmbeddedSourceSettings;
      Scte20SourceSettings?: Scte20SourceSettings;
      Scte27SourceSettings?: Scte27SourceSettings;
      TeletextSourceSettings?: TeletextSourceSettings;
    }
    export interface CdiInputSpecification {
      Resolution?: string;
    }
    export interface ColorSpacePassthroughSettings {}
    export interface DvbNitSettings {
      NetworkId?: number;
      NetworkName?: string;
      RepInterval?: number;
    }
    export interface DvbSdtSettings {
      OutputSdt?: string;
      RepInterval?: number;
      ServiceName?: string;
      ServiceProviderName?: string;
    }
    export interface DvbSubDestinationSettings {
      Alignment?: string;
      BackgroundColor?: string;
      BackgroundOpacity?: number;
      Font?: InputLocation;
      FontColor?: string;
      FontOpacity?: number;
      FontResolution?: number;
      FontSize?: string;
      OutlineColor?: string;
      OutlineSize?: number;
      ShadowColor?: string;
      ShadowOpacity?: number;
      ShadowXOffset?: number;
      ShadowYOffset?: number;
      TeletextGridControl?: string;
      XPosition?: number;
      YPosition?: number;
    }
    export interface DvbSubSourceSettings {
      OcrLanguage?: string;
      Pid?: number;
    }
    export interface DvbTdtSettings {
      RepInterval?: number;
    }
    export interface Eac3Settings {
      AttenuationControl?: string;
      Bitrate?: number;
      BitstreamMode?: string;
      CodingMode?: string;
      DcFilter?: string;
      Dialnorm?: number;
      DrcLine?: string;
      DrcRf?: string;
      LfeControl?: string;
      LfeFilter?: string;
      LoRoCenterMixLevel?: number;
      LoRoSurroundMixLevel?: number;
      LtRtCenterMixLevel?: number;
      LtRtSurroundMixLevel?: number;
      MetadataControl?: string;
      PassthroughControl?: string;
      PhaseControl?: string;
      StereoDownmix?: string;
      SurroundExMode?: string;
      SurroundMode?: string;
    }
    export interface EbuTtDDestinationSettings {
      CopyrightHolder?: string;
      FillLineGap?: string;
      FontFamily?: string;
      StyleControl?: string;
    }
    export interface EmbeddedDestinationSettings {}
    export interface EmbeddedPlusScte20DestinationSettings {}
    export interface EmbeddedSourceSettings {
      Convert608To708?: string;
      Scte20Detection?: string;
      Source608ChannelNumber?: number;
      Source608TrackNumber?: number;
    }
    export interface EncoderSettings {
      AudioDescriptions?: AudioDescription[];
      AvailBlanking?: AvailBlanking;
      AvailConfiguration?: AvailConfiguration;
      BlackoutSlate?: BlackoutSlate;
      CaptionDescriptions?: CaptionDescription[];
      FeatureActivations?: FeatureActivations;
      GlobalConfiguration?: GlobalConfiguration;
      MotionGraphicsConfiguration?: MotionGraphicsConfiguration;
      NielsenConfiguration?: NielsenConfiguration;
      OutputGroups?: OutputGroup[];
      TimecodeConfig?: TimecodeConfig;
      VideoDescriptions?: VideoDescription[];
    }
    export interface FailoverCondition {
      FailoverConditionSettings?: FailoverConditionSettings;
    }
    export interface FailoverConditionSettings {
      AudioSilenceSettings?: AudioSilenceFailoverSettings;
      InputLossSettings?: InputLossFailoverSettings;
      VideoBlackSettings?: VideoBlackFailoverSettings;
    }
    export interface FeatureActivations {
      InputPrepareScheduleActions?: string;
    }
    export interface FecOutputSettings {
      ColumnDepth?: number;
      IncludeFec?: string;
      RowLength?: number;
    }
    export interface Fmp4HlsSettings {
      AudioRenditionSets?: string;
      NielsenId3Behavior?: string;
      TimedMetadataBehavior?: string;
    }
    export interface FrameCaptureCdnSettings {
      FrameCaptureS3Settings?: FrameCaptureS3Settings;
    }
    export interface FrameCaptureGroupSettings {
      Destination?: OutputLocationRef;
      FrameCaptureCdnSettings?: FrameCaptureCdnSettings;
    }
    export interface FrameCaptureHlsSettings {}
    export interface FrameCaptureOutputSettings {
      NameModifier?: string;
    }
    export interface FrameCaptureS3Settings {
      CannedAcl?: string;
    }
    export interface FrameCaptureSettings {
      CaptureInterval?: number;
      CaptureIntervalUnits?: string;
    }
    export interface GlobalConfiguration {
      InitialAudioGain?: number;
      InputEndAction?: string;
      InputLossBehavior?: InputLossBehavior;
      OutputLockingMode?: string;
      OutputTimingSource?: string;
      SupportLowFramerateInputs?: string;
    }
    export interface H264ColorSpaceSettings {
      ColorSpacePassthroughSettings?: ColorSpacePassthroughSettings;
      Rec601Settings?: Rec601Settings;
      Rec709Settings?: Rec709Settings;
    }
    export interface H264FilterSettings {
      TemporalFilterSettings?: TemporalFilterSettings;
    }
    export interface H264Settings {
      AdaptiveQuantization?: string;
      AfdSignaling?: string;
      Bitrate?: number;
      BufFillPct?: number;
      BufSize?: number;
      ColorMetadata?: string;
      ColorSpaceSettings?: H264ColorSpaceSettings;
      EntropyEncoding?: string;
      FilterSettings?: H264FilterSettings;
      FixedAfd?: string;
      FlickerAq?: string;
      ForceFieldPictures?: string;
      FramerateControl?: string;
      FramerateDenominator?: number;
      FramerateNumerator?: number;
      GopBReference?: string;
      GopClosedCadence?: number;
      GopNumBFrames?: number;
      GopSize?: number;
      GopSizeUnits?: string;
      Level?: string;
      LookAheadRateControl?: string;
      MaxBitrate?: number;
      MinIInterval?: number;
      NumRefFrames?: number;
      ParControl?: string;
      ParDenominator?: number;
      ParNumerator?: number;
      Profile?: string;
      QualityLevel?: string;
      QvbrQualityLevel?: number;
      RateControlMode?: string;
      ScanType?: string;
      SceneChangeDetect?: string;
      Slices?: number;
      Softness?: number;
      SpatialAq?: string;
      SubgopLength?: string;
      Syntax?: string;
      TemporalAq?: string;
      TimecodeInsertion?: string;
    }
    export interface H265ColorSpaceSettings {
      ColorSpacePassthroughSettings?: ColorSpacePassthroughSettings;
      Hdr10Settings?: Hdr10Settings;
      Rec601Settings?: Rec601Settings;
      Rec709Settings?: Rec709Settings;
    }
    export interface H265FilterSettings {
      TemporalFilterSettings?: TemporalFilterSettings;
    }
    export interface H265Settings {
      AdaptiveQuantization?: string;
      AfdSignaling?: string;
      AlternativeTransferFunction?: string;
      Bitrate?: number;
      BufSize?: number;
      ColorMetadata?: string;
      ColorSpaceSettings?: H265ColorSpaceSettings;
      FilterSettings?: H265FilterSettings;
      FixedAfd?: string;
      FlickerAq?: string;
      FramerateDenominator?: number;
      FramerateNumerator?: number;
      GopClosedCadence?: number;
      GopSize?: number;
      GopSizeUnits?: string;
      Level?: string;
      LookAheadRateControl?: string;
      MaxBitrate?: number;
      MinIInterval?: number;
      ParDenominator?: number;
      ParNumerator?: number;
      Profile?: string;
      QvbrQualityLevel?: number;
      RateControlMode?: string;
      ScanType?: string;
      SceneChangeDetect?: string;
      Slices?: number;
      Tier?: string;
      TimecodeInsertion?: string;
    }
    export interface Hdr10Settings {
      MaxCll?: number;
      MaxFall?: number;
    }
    export interface HlsAkamaiSettings {
      ConnectionRetryInterval?: number;
      FilecacheDuration?: number;
      HttpTransferMode?: string;
      NumRetries?: number;
      RestartDelay?: number;
      Salt?: string;
      Token?: string;
    }
    export interface HlsBasicPutSettings {
      ConnectionRetryInterval?: number;
      FilecacheDuration?: number;
      NumRetries?: number;
      RestartDelay?: number;
    }
    export interface HlsCdnSettings {
      HlsAkamaiSettings?: HlsAkamaiSettings;
      HlsBasicPutSettings?: HlsBasicPutSettings;
      HlsMediaStoreSettings?: HlsMediaStoreSettings;
      HlsS3Settings?: HlsS3Settings;
      HlsWebdavSettings?: HlsWebdavSettings;
    }
    export interface HlsGroupSettings {
      AdMarkers?: string[];
      BaseUrlContent?: string;
      BaseUrlContent1?: string;
      BaseUrlManifest?: string;
      BaseUrlManifest1?: string;
      CaptionLanguageMappings?: CaptionLanguageMapping[];
      CaptionLanguageSetting?: string;
      ClientCache?: string;
      CodecSpecification?: string;
      ConstantIv?: string;
      Destination?: OutputLocationRef;
      DirectoryStructure?: string;
      DiscontinuityTags?: string;
      EncryptionType?: string;
      HlsCdnSettings?: HlsCdnSettings;
      HlsId3SegmentTagging?: string;
      IFrameOnlyPlaylists?: string;
      IncompleteSegmentBehavior?: string;
      IndexNSegments?: number;
      InputLossAction?: string;
      IvInManifest?: string;
      IvSource?: string;
      KeepSegments?: number;
      KeyFormat?: string;
      KeyFormatVersions?: string;
      KeyProviderSettings?: KeyProviderSettings;
      ManifestCompression?: string;
      ManifestDurationFormat?: string;
      MinSegmentLength?: number;
      Mode?: string;
      OutputSelection?: string;
      ProgramDateTime?: string;
      ProgramDateTimeClock?: string;
      ProgramDateTimePeriod?: number;
      RedundantManifest?: string;
      SegmentLength?: number;
      SegmentationMode?: string;
      SegmentsPerSubdirectory?: number;
      StreamInfResolution?: string;
      TimedMetadataId3Frame?: string;
      TimedMetadataId3Period?: number;
      TimestampDeltaMilliseconds?: number;
      TsFileMode?: string;
    }
    export interface HlsInputSettings {
      Bandwidth?: number;
      BufferSegments?: number;
      Retries?: number;
      RetryInterval?: number;
      Scte35Source?: string;
    }
    export interface HlsMediaStoreSettings {
      ConnectionRetryInterval?: number;
      FilecacheDuration?: number;
      MediaStoreStorageClass?: string;
      NumRetries?: number;
      RestartDelay?: number;
    }
    export interface HlsOutputSettings {
      H265PackagingType?: string;
      HlsSettings?: HlsSettings;
      NameModifier?: string;
      SegmentModifier?: string;
    }
    export interface HlsS3Settings {
      CannedAcl?: string;
    }
    export interface HlsSettings {
      AudioOnlyHlsSettings?: AudioOnlyHlsSettings;
      Fmp4HlsSettings?: Fmp4HlsSettings;
      FrameCaptureHlsSettings?: FrameCaptureHlsSettings;
      StandardHlsSettings?: StandardHlsSettings;
    }
    export interface HlsWebdavSettings {
      ConnectionRetryInterval?: number;
      FilecacheDuration?: number;
      HttpTransferMode?: string;
      NumRetries?: number;
      RestartDelay?: number;
    }
    export interface HtmlMotionGraphicsSettings {}
    export interface InputAttachment {
      AutomaticInputFailoverSettings?: AutomaticInputFailoverSettings;
      InputAttachmentName?: string;
      InputId?: string;
      InputSettings?: InputSettings;
    }
    export interface InputChannelLevel {
      Gain?: number;
      InputChannel?: number;
    }
    export interface InputLocation {
      PasswordParam?: string;
      Uri?: string;
      Username?: string;
    }
    export interface InputLossBehavior {
      BlackFrameMsec?: number;
      InputLossImageColor?: string;
      InputLossImageSlate?: InputLocation;
      InputLossImageType?: string;
      RepeatFrameMsec?: number;
    }
    export interface InputLossFailoverSettings {
      InputLossThresholdMsec?: number;
    }
    export interface InputSettings {
      AudioSelectors?: AudioSelector[];
      CaptionSelectors?: CaptionSelector[];
      DeblockFilter?: string;
      DenoiseFilter?: string;
      FilterStrength?: number;
      InputFilter?: string;
      NetworkInputSettings?: NetworkInputSettings;
      Scte35Pid?: number;
      Smpte2038DataPreference?: string;
      SourceEndBehavior?: string;
      VideoSelector?: VideoSelector;
    }
    export interface InputSpecification {
      Codec?: string;
      MaximumBitrate?: string;
      Resolution?: string;
    }
    export interface KeyProviderSettings {
      StaticKeySettings?: StaticKeySettings;
    }
    export interface M2tsSettings {
      AbsentInputAudioBehavior?: string;
      Arib?: string;
      AribCaptionsPid?: string;
      AribCaptionsPidControl?: string;
      AudioBufferModel?: string;
      AudioFramesPerPes?: number;
      AudioPids?: string;
      AudioStreamType?: string;
      Bitrate?: number;
      BufferModel?: string;
      CcDescriptor?: string;
      DvbNitSettings?: DvbNitSettings;
      DvbSdtSettings?: DvbSdtSettings;
      DvbSubPids?: string;
      DvbTdtSettings?: DvbTdtSettings;
      DvbTeletextPid?: string;
      Ebif?: string;
      EbpAudioInterval?: string;
      EbpLookaheadMs?: number;
      EbpPlacement?: string;
      EcmPid?: string;
      EsRateInPes?: string;
      EtvPlatformPid?: string;
      EtvSignalPid?: string;
      FragmentTime?: number;
      Klv?: string;
      KlvDataPids?: string;
      NielsenId3Behavior?: string;
      NullPacketBitrate?: number;
      PatInterval?: number;
      PcrControl?: string;
      PcrPeriod?: number;
      PcrPid?: string;
      PmtInterval?: number;
      PmtPid?: string;
      ProgramNum?: number;
      RateMode?: string;
      Scte27Pids?: string;
      Scte35Control?: string;
      Scte35Pid?: string;
      SegmentationMarkers?: string;
      SegmentationStyle?: string;
      SegmentationTime?: number;
      TimedMetadataBehavior?: string;
      TimedMetadataPid?: string;
      TransportStreamId?: number;
      VideoPid?: string;
    }
    export interface M3u8Settings {
      AudioFramesPerPes?: number;
      AudioPids?: string;
      EcmPid?: string;
      NielsenId3Behavior?: string;
      PatInterval?: number;
      PcrControl?: string;
      PcrPeriod?: number;
      PcrPid?: string;
      PmtInterval?: number;
      PmtPid?: string;
      ProgramNum?: number;
      Scte35Behavior?: string;
      Scte35Pid?: string;
      TimedMetadataBehavior?: string;
      TimedMetadataPid?: string;
      TransportStreamId?: number;
      VideoPid?: string;
    }
    export interface MediaPackageGroupSettings {
      Destination?: OutputLocationRef;
    }
    export interface MediaPackageOutputDestinationSettings {
      ChannelId?: string;
    }
    export interface MediaPackageOutputSettings {}
    export interface MotionGraphicsConfiguration {
      MotionGraphicsInsertion?: string;
      MotionGraphicsSettings?: MotionGraphicsSettings;
    }
    export interface MotionGraphicsSettings {
      HtmlMotionGraphicsSettings?: HtmlMotionGraphicsSettings;
    }
    export interface Mp2Settings {
      Bitrate?: number;
      CodingMode?: string;
      SampleRate?: number;
    }
    export interface Mpeg2FilterSettings {
      TemporalFilterSettings?: TemporalFilterSettings;
    }
    export interface Mpeg2Settings {
      AdaptiveQuantization?: string;
      AfdSignaling?: string;
      ColorMetadata?: string;
      ColorSpace?: string;
      DisplayAspectRatio?: string;
      FilterSettings?: Mpeg2FilterSettings;
      FixedAfd?: string;
      FramerateDenominator?: number;
      FramerateNumerator?: number;
      GopClosedCadence?: number;
      GopNumBFrames?: number;
      GopSize?: number;
      GopSizeUnits?: string;
      ScanType?: string;
      SubgopLength?: string;
      TimecodeInsertion?: string;
    }
    export interface MsSmoothGroupSettings {
      AcquisitionPointId?: string;
      AudioOnlyTimecodeControl?: string;
      CertificateMode?: string;
      ConnectionRetryInterval?: number;
      Destination?: OutputLocationRef;
      EventId?: string;
      EventIdMode?: string;
      EventStopBehavior?: string;
      FilecacheDuration?: number;
      FragmentLength?: number;
      InputLossAction?: string;
      NumRetries?: number;
      RestartDelay?: number;
      SegmentationMode?: string;
      SendDelayMs?: number;
      SparseTrackType?: string;
      StreamManifestBehavior?: string;
      TimestampOffset?: string;
      TimestampOffsetMode?: string;
    }
    export interface MsSmoothOutputSettings {
      H265PackagingType?: string;
      NameModifier?: string;
    }
    export interface MultiplexGroupSettings {}
    export interface MultiplexOutputSettings {
      Destination?: OutputLocationRef;
    }
    export interface MultiplexProgramChannelDestinationSettings {
      MultiplexId?: string;
      ProgramName?: string;
    }
    export interface NetworkInputSettings {
      HlsInputSettings?: HlsInputSettings;
      ServerValidation?: string;
    }
    export interface NielsenCBET {
      CbetCheckDigitString?: string;
      CbetStepaside?: string;
      Csid?: string;
    }
    export interface NielsenConfiguration {
      DistributorId?: string;
      NielsenPcmToId3Tagging?: string;
    }
    export interface NielsenNaesIiNw {
      CheckDigitString?: string;
      Sid?: number;
    }
    export interface NielsenWatermarksSettings {
      NielsenCbetSettings?: NielsenCBET;
      NielsenDistributionType?: string;
      NielsenNaesIiNwSettings?: NielsenNaesIiNw;
    }
    export interface Output {
      AudioDescriptionNames?: string[];
      CaptionDescriptionNames?: string[];
      OutputName?: string;
      OutputSettings?: OutputSettings;
      VideoDescriptionName?: string;
    }
    export interface OutputDestination {
      Id?: string;
      MediaPackageSettings?: MediaPackageOutputDestinationSettings[];
      MultiplexSettings?: MultiplexProgramChannelDestinationSettings;
      Settings?: OutputDestinationSettings[];
    }
    export interface OutputDestinationSettings {
      PasswordParam?: string;
      StreamName?: string;
      Url?: string;
      Username?: string;
    }
    export interface OutputGroup {
      Name?: string;
      OutputGroupSettings?: OutputGroupSettings;
      Outputs?: Output[];
    }
    export interface OutputGroupSettings {
      ArchiveGroupSettings?: ArchiveGroupSettings;
      FrameCaptureGroupSettings?: FrameCaptureGroupSettings;
      HlsGroupSettings?: HlsGroupSettings;
      MediaPackageGroupSettings?: MediaPackageGroupSettings;
      MsSmoothGroupSettings?: MsSmoothGroupSettings;
      MultiplexGroupSettings?: MultiplexGroupSettings;
      RtmpGroupSettings?: RtmpGroupSettings;
      UdpGroupSettings?: UdpGroupSettings;
    }
    export interface OutputLocationRef {
      DestinationRefId?: string;
    }
    export interface OutputSettings {
      ArchiveOutputSettings?: ArchiveOutputSettings;
      FrameCaptureOutputSettings?: FrameCaptureOutputSettings;
      HlsOutputSettings?: HlsOutputSettings;
      MediaPackageOutputSettings?: MediaPackageOutputSettings;
      MsSmoothOutputSettings?: MsSmoothOutputSettings;
      MultiplexOutputSettings?: MultiplexOutputSettings;
      RtmpOutputSettings?: RtmpOutputSettings;
      UdpOutputSettings?: UdpOutputSettings;
    }
    export interface PassThroughSettings {}
    export interface RawSettings {}
    export interface Rec601Settings {}
    export interface Rec709Settings {}
    export interface RemixSettings {
      ChannelMappings?: AudioChannelMapping[];
      ChannelsIn?: number;
      ChannelsOut?: number;
    }
    export interface RtmpCaptionInfoDestinationSettings {}
    export interface RtmpGroupSettings {
      AdMarkers?: string[];
      AuthenticationScheme?: string;
      CacheFullBehavior?: string;
      CacheLength?: number;
      CaptionData?: string;
      InputLossAction?: string;
      RestartDelay?: number;
    }
    export interface RtmpOutputSettings {
      CertificateMode?: string;
      ConnectionRetryInterval?: number;
      Destination?: OutputLocationRef;
      NumRetries?: number;
    }
    export interface Scte20PlusEmbeddedDestinationSettings {}
    export interface Scte20SourceSettings {
      Convert608To708?: string;
      Source608ChannelNumber?: number;
    }
    export interface Scte27DestinationSettings {}
    export interface Scte27SourceSettings {
      OcrLanguage?: string;
      Pid?: number;
    }
    export interface Scte35SpliceInsert {
      AdAvailOffset?: number;
      NoRegionalBlackoutFlag?: string;
      WebDeliveryAllowedFlag?: string;
    }
    export interface Scte35TimeSignalApos {
      AdAvailOffset?: number;
      NoRegionalBlackoutFlag?: string;
      WebDeliveryAllowedFlag?: string;
    }
    export interface SmpteTtDestinationSettings {}
    export interface StandardHlsSettings {
      AudioRenditionSets?: string;
      M3u8Settings?: M3u8Settings;
    }
    export interface StaticKeySettings {
      KeyProviderServer?: InputLocation;
      StaticKeyValue?: string;
    }
    export interface TeletextDestinationSettings {}
    export interface TeletextSourceSettings {
      OutputRectangle?: CaptionRectangle;
      PageNumber?: string;
    }
    export interface TemporalFilterSettings {
      PostFilterSharpening?: string;
      Strength?: string;
    }
    export interface TimecodeConfig {
      Source?: string;
      SyncThreshold?: number;
    }
    export interface TtmlDestinationSettings {
      StyleControl?: string;
    }
    export interface UdpContainerSettings {
      M2tsSettings?: M2tsSettings;
    }
    export interface UdpGroupSettings {
      InputLossAction?: string;
      TimedMetadataId3Frame?: string;
      TimedMetadataId3Period?: number;
    }
    export interface UdpOutputSettings {
      BufferMsec?: number;
      ContainerSettings?: UdpContainerSettings;
      Destination?: OutputLocationRef;
      FecOutputSettings?: FecOutputSettings;
    }
    export interface VideoBlackFailoverSettings {
      BlackDetectThreshold?: number;
      VideoBlackThresholdMsec?: number;
    }
    export interface VideoCodecSettings {
      FrameCaptureSettings?: FrameCaptureSettings;
      H264Settings?: H264Settings;
      H265Settings?: H265Settings;
      Mpeg2Settings?: Mpeg2Settings;
    }
    export interface VideoDescription {
      CodecSettings?: VideoCodecSettings;
      Height?: number;
      Name?: string;
      RespondToAfd?: string;
      ScalingBehavior?: string;
      Sharpness?: number;
      Width?: number;
    }
    export interface VideoSelector {
      ColorSpace?: string;
      ColorSpaceSettings?: VideoSelectorColorSpaceSettings;
      ColorSpaceUsage?: string;
      SelectorSettings?: VideoSelectorSettings;
    }
    export interface VideoSelectorColorSpaceSettings {
      Hdr10Settings?: Hdr10Settings;
    }
    export interface VideoSelectorPid {
      Pid?: number;
    }
    export interface VideoSelectorProgramId {
      ProgramId?: number;
    }
    export interface VideoSelectorSettings {
      VideoSelectorPid?: VideoSelectorPid;
      VideoSelectorProgramId?: VideoSelectorProgramId;
    }
    export interface VpcOutputSettings {
      PublicAddressAllocationIds?: string[];
      SecurityGroupIds?: string[];
      SubnetIds?: string[];
    }
    export interface WavSettings {
      BitDepth?: number;
      CodingMode?: string;
      SampleRate?: number;
    }
    export interface WebvttDestinationSettings {
      StyleControl?: string;
    }
  }
  export interface Input {
    Destinations?: Input.InputDestinationRequest[];
    InputDevices?: Input.InputDeviceSettings[];
    InputSecurityGroups?: string[];
    MediaConnectFlows?: Input.MediaConnectFlowRequest[];
    Name?: string;
    RoleArn?: string;
    Sources?: Input.InputSourceRequest[];
    Tags?: any;
    Type?: string;
    Vpc?: Input.InputVpcRequest;
  }
  export namespace Input {
    export interface Attr {
      Arn: string;
      Destinations: string[];
      Sources: string[];
    }
    export interface InputDestinationRequest {
      StreamName?: string;
    }
    export interface InputDeviceRequest {
      Id?: string;
    }
    export interface InputDeviceSettings {
      Id?: string;
    }
    export interface InputSourceRequest {
      PasswordParam?: string;
      Url?: string;
      Username?: string;
    }
    export interface InputVpcRequest {
      SecurityGroupIds?: string[];
      SubnetIds?: string[];
    }
    export interface MediaConnectFlowRequest {
      FlowArn?: string;
    }
  }
  export interface InputSecurityGroup {
    Tags?: any;
    WhitelistRules?: InputSecurityGroup.InputWhitelistRuleCidr[];
  }
  export namespace InputSecurityGroup {
    export interface Attr {
      Arn: string;
    }
    export interface InputWhitelistRuleCidr {
      Cidr?: string;
    }
  }
}
export namespace MediaPackage {
  export interface Asset {
    Id: string;
    PackagingGroupId: string;
    ResourceId?: string;
    SourceArn: string;
    SourceRoleArn: string;
    Tags?: Tag[];
  }
  export namespace Asset {
    export interface Attr {
      Arn: string;
      CreatedAt: string;
      EgressEndpoints: EgressEndpoint[];
    }
    export interface EgressEndpoint {
      PackagingConfigurationId: string;
      Url: string;
    }
  }
  export interface Channel {
    Description?: string;
    EgressAccessLogs?: Channel.LogConfiguration;
    HlsIngest?: Channel.HlsIngest;
    Id: string;
    IngressAccessLogs?: Channel.LogConfiguration;
    Tags?: Tag[];
  }
  export namespace Channel {
    export interface Attr {
      Arn: string;
    }
    export interface HlsIngest {
      ingestEndpoints?: IngestEndpoint[];
    }
    export interface IngestEndpoint {
      Id: string;
      Password: string;
      Url: string;
      Username: string;
    }
    export interface LogConfiguration {
      LogGroupName?: string;
    }
  }
  export interface OriginEndpoint {
    Authorization?: OriginEndpoint.Authorization;
    ChannelId: string;
    CmafPackage?: OriginEndpoint.CmafPackage;
    DashPackage?: OriginEndpoint.DashPackage;
    Description?: string;
    HlsPackage?: OriginEndpoint.HlsPackage;
    Id: string;
    ManifestName?: string;
    MssPackage?: OriginEndpoint.MssPackage;
    Origination?: string;
    StartoverWindowSeconds?: number;
    Tags?: Tag[];
    TimeDelaySeconds?: number;
    Whitelist?: string[];
  }
  export namespace OriginEndpoint {
    export interface Attr {
      Arn: string;
      Url: string;
    }
    export interface Authorization {
      CdnIdentifierSecret: string;
      SecretsRoleArn: string;
    }
    export interface CmafEncryption {
      ConstantInitializationVector?: string;
      EncryptionMethod?: string;
      KeyRotationIntervalSeconds?: number;
      SpekeKeyProvider: SpekeKeyProvider;
    }
    export interface CmafPackage {
      Encryption?: CmafEncryption;
      HlsManifests?: HlsManifest[];
      SegmentDurationSeconds?: number;
      SegmentPrefix?: string;
      StreamSelection?: StreamSelection;
    }
    export interface DashEncryption {
      KeyRotationIntervalSeconds?: number;
      SpekeKeyProvider: SpekeKeyProvider;
    }
    export interface DashPackage {
      AdTriggers?: string[];
      AdsOnDeliveryRestrictions?: string;
      Encryption?: DashEncryption;
      IncludeIframeOnlyStream?: boolean;
      ManifestLayout?: string;
      ManifestWindowSeconds?: number;
      MinBufferTimeSeconds?: number;
      MinUpdatePeriodSeconds?: number;
      PeriodTriggers?: string[];
      Profile?: string;
      SegmentDurationSeconds?: number;
      SegmentTemplateFormat?: string;
      StreamSelection?: StreamSelection;
      SuggestedPresentationDelaySeconds?: number;
      UtcTiming?: string;
      UtcTimingUri?: string;
    }
    export interface EncryptionContractConfiguration {
      PresetSpeke20Audio: string;
      PresetSpeke20Video: string;
    }
    export interface HlsEncryption {
      ConstantInitializationVector?: string;
      EncryptionMethod?: string;
      KeyRotationIntervalSeconds?: number;
      RepeatExtXKey?: boolean;
      SpekeKeyProvider: SpekeKeyProvider;
    }
    export interface HlsManifest {
      AdMarkers?: string;
      AdTriggers?: string[];
      AdsOnDeliveryRestrictions?: string;
      Id: string;
      IncludeIframeOnlyStream?: boolean;
      ManifestName?: string;
      PlaylistType?: string;
      PlaylistWindowSeconds?: number;
      ProgramDateTimeIntervalSeconds?: number;
      Url?: string;
    }
    export interface HlsPackage {
      AdMarkers?: string;
      AdTriggers?: string[];
      AdsOnDeliveryRestrictions?: string;
      Encryption?: HlsEncryption;
      IncludeDvbSubtitles?: boolean;
      IncludeIframeOnlyStream?: boolean;
      PlaylistType?: string;
      PlaylistWindowSeconds?: number;
      ProgramDateTimeIntervalSeconds?: number;
      SegmentDurationSeconds?: number;
      StreamSelection?: StreamSelection;
      UseAudioRenditionGroup?: boolean;
    }
    export interface MssEncryption {
      SpekeKeyProvider: SpekeKeyProvider;
    }
    export interface MssPackage {
      Encryption?: MssEncryption;
      ManifestWindowSeconds?: number;
      SegmentDurationSeconds?: number;
      StreamSelection?: StreamSelection;
    }
    export interface SpekeKeyProvider {
      CertificateArn?: string;
      EncryptionContractConfiguration?: EncryptionContractConfiguration;
      ResourceId: string;
      RoleArn: string;
      SystemIds: string[];
      Url: string;
    }
    export interface StreamSelection {
      MaxVideoBitsPerSecond?: number;
      MinVideoBitsPerSecond?: number;
      StreamOrder?: string;
    }
  }
  export interface PackagingConfiguration {
    CmafPackage?: PackagingConfiguration.CmafPackage;
    DashPackage?: PackagingConfiguration.DashPackage;
    HlsPackage?: PackagingConfiguration.HlsPackage;
    Id: string;
    MssPackage?: PackagingConfiguration.MssPackage;
    PackagingGroupId: string;
    Tags?: Tag[];
  }
  export namespace PackagingConfiguration {
    export interface Attr {
      Arn: string;
    }
    export interface CmafEncryption {
      SpekeKeyProvider: SpekeKeyProvider;
    }
    export interface CmafPackage {
      Encryption?: CmafEncryption;
      HlsManifests: HlsManifest[];
      IncludeEncoderConfigurationInSegments?: boolean;
      SegmentDurationSeconds?: number;
    }
    export interface DashEncryption {
      SpekeKeyProvider: SpekeKeyProvider;
    }
    export interface DashManifest {
      ManifestLayout?: string;
      ManifestName?: string;
      MinBufferTimeSeconds?: number;
      Profile?: string;
      ScteMarkersSource?: string;
      StreamSelection?: StreamSelection;
    }
    export interface DashPackage {
      DashManifests: DashManifest[];
      Encryption?: DashEncryption;
      IncludeEncoderConfigurationInSegments?: boolean;
      IncludeIframeOnlyStream?: boolean;
      PeriodTriggers?: string[];
      SegmentDurationSeconds?: number;
      SegmentTemplateFormat?: string;
    }
    export interface EncryptionContractConfiguration {
      PresetSpeke20Audio: string;
      PresetSpeke20Video: string;
    }
    export interface HlsEncryption {
      ConstantInitializationVector?: string;
      EncryptionMethod?: string;
      SpekeKeyProvider: SpekeKeyProvider;
    }
    export interface HlsManifest {
      AdMarkers?: string;
      IncludeIframeOnlyStream?: boolean;
      ManifestName?: string;
      ProgramDateTimeIntervalSeconds?: number;
      RepeatExtXKey?: boolean;
      StreamSelection?: StreamSelection;
    }
    export interface HlsPackage {
      Encryption?: HlsEncryption;
      HlsManifests: HlsManifest[];
      IncludeDvbSubtitles?: boolean;
      SegmentDurationSeconds?: number;
      UseAudioRenditionGroup?: boolean;
    }
    export interface MssEncryption {
      SpekeKeyProvider: SpekeKeyProvider;
    }
    export interface MssManifest {
      ManifestName?: string;
      StreamSelection?: StreamSelection;
    }
    export interface MssPackage {
      Encryption?: MssEncryption;
      MssManifests: MssManifest[];
      SegmentDurationSeconds?: number;
    }
    export interface SpekeKeyProvider {
      EncryptionContractConfiguration?: EncryptionContractConfiguration;
      RoleArn: string;
      SystemIds: string[];
      Url: string;
    }
    export interface StreamSelection {
      MaxVideoBitsPerSecond?: number;
      MinVideoBitsPerSecond?: number;
      StreamOrder?: string;
    }
  }
  export interface PackagingGroup {
    Authorization?: PackagingGroup.Authorization;
    EgressAccessLogs?: PackagingGroup.LogConfiguration;
    Id: string;
    Tags?: Tag[];
  }
  export namespace PackagingGroup {
    export interface Attr {
      Arn: string;
      DomainName: string;
    }
    export interface Authorization {
      CdnIdentifierSecret: string;
      SecretsRoleArn: string;
    }
    export interface LogConfiguration {
      LogGroupName?: string;
    }
  }
}
export namespace MediaStore {
  export interface Container {
    AccessLoggingEnabled?: boolean;
    ContainerName: string;
    CorsPolicy?: Container.CorsRule[];
    LifecyclePolicy?: string;
    MetricPolicy?: Container.MetricPolicy;
    Policy?: string;
    Tags?: Tag[];
  }
  export namespace Container {
    export interface Attr {
      Endpoint: string;
    }
    export interface CorsRule {
      AllowedHeaders?: string[];
      AllowedMethods?: string[];
      AllowedOrigins?: string[];
      ExposeHeaders?: string[];
      MaxAgeSeconds?: number;
    }
    export interface MetricPolicy {
      ContainerLevelMetrics: string;
      MetricPolicyRules?: MetricPolicyRule[];
    }
    export interface MetricPolicyRule {
      ObjectGroup: string;
      ObjectGroupName: string;
    }
  }
}
export namespace MediaTailor {
  export interface PlaybackConfiguration {
    AdDecisionServerUrl: string;
    AvailSuppression?: PlaybackConfiguration.AvailSuppression;
    Bumper?: PlaybackConfiguration.Bumper;
    CdnConfiguration?: PlaybackConfiguration.CdnConfiguration;
    ConfigurationAliases?: Record<string, any>;
    DashConfiguration?: PlaybackConfiguration.DashConfiguration;
    HlsConfiguration?: PlaybackConfiguration.HlsConfiguration;
    LivePreRollConfiguration?: PlaybackConfiguration.LivePreRollConfiguration;
    ManifestProcessingRules?: PlaybackConfiguration.ManifestProcessingRules;
    Name: string;
    PersonalizationThresholdSeconds?: number;
    SlateAdUrl?: string;
    Tags?: Tag[];
    TranscodeProfileName?: string;
    VideoContentSourceUrl: string;
  }
  export namespace PlaybackConfiguration {
    export interface Attr {
      "DashConfiguration.ManifestEndpointPrefix": string;
      "HlsConfiguration.ManifestEndpointPrefix": string;
      PlaybackConfigurationArn: string;
      PlaybackEndpointPrefix: string;
      SessionInitializationEndpointPrefix: string;
    }
    export interface AdMarkerPassthrough {
      Enabled?: boolean;
    }
    export interface AvailSuppression {
      Mode?: string;
      Value?: string;
    }
    export interface Bumper {
      EndUrl?: string;
      StartUrl?: string;
    }
    export interface CdnConfiguration {
      AdSegmentUrlPrefix?: string;
      ContentSegmentUrlPrefix?: string;
    }
    export interface DashConfiguration {
      ManifestEndpointPrefix?: string;
      MpdLocation?: string;
      OriginManifestType?: string;
    }
    export interface HlsConfiguration {
      ManifestEndpointPrefix?: string;
    }
    export interface LivePreRollConfiguration {
      AdDecisionServerUrl?: string;
      MaxDurationSeconds?: number;
    }
    export interface ManifestProcessingRules {
      AdMarkerPassthrough?: AdMarkerPassthrough;
    }
  }
}
export namespace MemoryDB {
  export interface ACL {
    ACLName: string;
    Tags?: Tag[];
    UserNames?: string[];
  }
  export interface Cluster {
    ACLName: string;
    AutoMinorVersionUpgrade?: boolean;
    ClusterEndpoint?: Cluster.Endpoint;
    ClusterName: string;
    DataTiering?: string;
    Description?: string;
    EngineVersion?: string;
    FinalSnapshotName?: string;
    KmsKeyId?: string;
    MaintenanceWindow?: string;
    NodeType: string;
    NumReplicasPerShard?: number;
    NumShards?: number;
    ParameterGroupName?: string;
    Port?: number;
    SecurityGroupIds?: string[];
    SnapshotArns?: string[];
    SnapshotName?: string;
    SnapshotRetentionLimit?: number;
    SnapshotWindow?: string;
    SnsTopicArn?: string;
    SnsTopicStatus?: string;
    SubnetGroupName?: string;
    TLSEnabled?: boolean;
    Tags?: Tag[];
  }
  export namespace Cluster {
    export interface Attr {
      ARN: string;
      "ClusterEndpoint.Address": string;
      "ClusterEndpoint.Port": number;
      ParameterGroupStatus: string;
      Status: string;
    }
    export interface Endpoint {
      Address?: string;
      Port?: number;
    }
  }
  export interface ParameterGroup {
    Description?: string;
    Family: string;
    ParameterGroupName: string;
    Parameters?: any;
    Tags?: Tag[];
  }
  export interface SubnetGroup {
    Description?: string;
    SubnetGroupName: string;
    SubnetIds: string[];
    Tags?: Tag[];
  }
  export interface User {
    AccessString: string;
    AuthenticationMode: any;
    Tags?: Tag[];
    UserName: string;
  }
  export namespace User {
    export interface Attr {
      Arn: string;
      Status: string;
    }
    export interface AuthenticationMode {
      Passwords?: string[];
      Type?: string;
    }
  }
}
export namespace Neptune {
  export interface DBCluster {
    AssociatedRoles?: DBCluster.DBClusterRole[];
    AvailabilityZones?: string[];
    BackupRetentionPeriod?: number;
    DBClusterIdentifier?: string;
    DBClusterParameterGroupName?: string;
    DBSubnetGroupName?: string;
    DeletionProtection?: boolean;
    EnableCloudwatchLogsExports?: string[];
    EngineVersion?: string;
    IamAuthEnabled?: boolean;
    KmsKeyId?: string;
    Port?: number;
    PreferredBackupWindow?: string;
    PreferredMaintenanceWindow?: string;
    RestoreToTime?: string;
    RestoreType?: string;
    SnapshotIdentifier?: string;
    SourceDBClusterIdentifier?: string;
    StorageEncrypted?: boolean;
    Tags?: Tag[];
    UseLatestRestorableTime?: boolean;
    VpcSecurityGroupIds?: string[];
  }
  export namespace DBCluster {
    export interface Attr {
      ClusterResourceId: string;
      Endpoint: string;
      Port: string;
      ReadEndpoint: string;
    }
    export interface DBClusterRole {
      FeatureName?: string;
      RoleArn: string;
    }
  }
  export interface DBClusterParameterGroup {
    Description: string;
    Family: string;
    Name?: string;
    Parameters: any;
    Tags?: Tag[];
  }
  export interface DBInstance {
    AllowMajorVersionUpgrade?: boolean;
    AutoMinorVersionUpgrade?: boolean;
    AvailabilityZone?: string;
    DBClusterIdentifier?: string;
    DBInstanceClass: string;
    DBInstanceIdentifier?: string;
    DBParameterGroupName?: string;
    DBSnapshotIdentifier?: string;
    DBSubnetGroupName?: string;
    PreferredMaintenanceWindow?: string;
    Tags?: Tag[];
  }
  export interface DBParameterGroup {
    Description: string;
    Family: string;
    Name?: string;
    Parameters: any;
    Tags?: Tag[];
  }
  export interface DBSubnetGroup {
    DBSubnetGroupDescription: string;
    DBSubnetGroupName?: string;
    SubnetIds: string[];
    Tags?: Tag[];
  }
}
export namespace NetworkFirewall {
  export interface Firewall {
    DeleteProtection?: boolean;
    Description?: string;
    FirewallName: string;
    FirewallPolicyArn: string;
    FirewallPolicyChangeProtection?: boolean;
    SubnetChangeProtection?: boolean;
    SubnetMappings: Firewall.SubnetMapping[];
    Tags?: Tag[];
    VpcId: string;
  }
  export namespace Firewall {
    export interface Attr {
      EndpointIds: string[];
      FirewallArn: string;
      FirewallId: string;
    }
    export interface SubnetMapping {
      SubnetId: string;
    }
  }
  export interface FirewallPolicy {
    Description?: string;
    FirewallPolicy: FirewallPolicy.FirewallPolicy;
    FirewallPolicyName: string;
    Tags?: Tag[];
  }
  export namespace FirewallPolicy {
    export interface Attr {
      FirewallPolicyArn: string;
      FirewallPolicyId: string;
    }
    export interface ActionDefinition {
      PublishMetricAction?: PublishMetricAction;
    }
    export interface CustomAction {
      ActionDefinition: ActionDefinition;
      ActionName: string;
    }
    export interface Dimension {
      Value: string;
    }
    export interface FirewallPolicy {
      StatefulDefaultActions?: string[];
      StatefulEngineOptions?: StatefulEngineOptions;
      StatefulRuleGroupReferences?: StatefulRuleGroupReference[];
      StatelessCustomActions?: CustomAction[];
      StatelessDefaultActions: string[];
      StatelessFragmentDefaultActions: string[];
      StatelessRuleGroupReferences?: StatelessRuleGroupReference[];
    }
    export interface PublishMetricAction {
      Dimensions: Dimension[];
    }
    export interface StatefulEngineOptions {
      RuleOrder?: string;
      StreamExceptionPolicy?: string;
    }
    export interface StatefulRuleGroupOverride {
      Action?: string;
    }
    export interface StatefulRuleGroupReference {
      Override?: StatefulRuleGroupOverride;
      Priority?: number;
      ResourceArn: string;
    }
    export interface StatelessRuleGroupReference {
      Priority: number;
      ResourceArn: string;
    }
  }
  export interface LoggingConfiguration {
    FirewallArn: string;
    FirewallName?: string;
    LoggingConfiguration: LoggingConfiguration.LoggingConfiguration;
  }
  export namespace LoggingConfiguration {
    export interface Attr {}
    export interface LogDestinationConfig {
      LogDestination: Record<string, string>;
      LogDestinationType: string;
      LogType: string;
    }
    export interface LoggingConfiguration {
      LogDestinationConfigs: LogDestinationConfig[];
    }
  }
  export interface RuleGroup {
    Capacity: number;
    Description?: string;
    RuleGroup?: RuleGroup.RuleGroup;
    RuleGroupName: string;
    Tags?: Tag[];
    Type: string;
  }
  export namespace RuleGroup {
    export interface Attr {
      RuleGroupArn: string;
      RuleGroupId: string;
    }
    export interface ActionDefinition {
      PublishMetricAction?: PublishMetricAction;
    }
    export interface Address {
      AddressDefinition: string;
    }
    export interface CustomAction {
      ActionDefinition: ActionDefinition;
      ActionName: string;
    }
    export interface Dimension {
      Value: string;
    }
    export interface Header {
      Destination: string;
      DestinationPort: string;
      Direction: string;
      Protocol: string;
      Source: string;
      SourcePort: string;
    }
    export interface IPSet {
      Definition?: string[];
    }
    export interface IPSetReference {
      ReferenceArn?: string;
    }
    export interface MatchAttributes {
      DestinationPorts?: PortRange[];
      Destinations?: Address[];
      Protocols?: number[];
      SourcePorts?: PortRange[];
      Sources?: Address[];
      TCPFlags?: TCPFlagField[];
    }
    export interface PortRange {
      FromPort: number;
      ToPort: number;
    }
    export interface PortSet {
      Definition?: string[];
    }
    export interface PublishMetricAction {
      Dimensions: Dimension[];
    }
    export interface ReferenceSets {
      IPSetReferences?: Record<string, IPSetReference>;
    }
    export interface RuleDefinition {
      Actions: string[];
      MatchAttributes: MatchAttributes;
    }
    export interface RuleGroup {
      ReferenceSets?: ReferenceSets;
      RuleVariables?: RuleVariables;
      RulesSource: RulesSource;
      StatefulRuleOptions?: StatefulRuleOptions;
    }
    export interface RuleOption {
      Keyword: string;
      Settings?: string[];
    }
    export interface RuleVariables {
      IPSets?: Record<string, IPSet>;
      PortSets?: Record<string, PortSet>;
    }
    export interface RulesSource {
      RulesSourceList?: RulesSourceList;
      RulesString?: string;
      StatefulRules?: StatefulRule[];
      StatelessRulesAndCustomActions?: StatelessRulesAndCustomActions;
    }
    export interface RulesSourceList {
      GeneratedRulesType: string;
      TargetTypes: string[];
      Targets: string[];
    }
    export interface StatefulRule {
      Action: string;
      Header: Header;
      RuleOptions: RuleOption[];
    }
    export interface StatefulRuleOptions {
      RuleOrder?: string;
    }
    export interface StatelessRule {
      Priority: number;
      RuleDefinition: RuleDefinition;
    }
    export interface StatelessRulesAndCustomActions {
      CustomActions?: CustomAction[];
      StatelessRules: StatelessRule[];
    }
    export interface TCPFlagField {
      Flags: string[];
      Masks?: string[];
    }
  }
}
export namespace NetworkManager {
  export interface ConnectAttachment {
    CoreNetworkId: string;
    EdgeLocation: string;
    Options: ConnectAttachment.ConnectAttachmentOptions;
    Tags?: Tag[];
    TransportAttachmentId: string;
  }
  export namespace ConnectAttachment {
    export interface Attr {
      AttachmentId: string;
      AttachmentPolicyRuleNumber: number;
      AttachmentType: string;
      CoreNetworkArn: string;
      CreatedAt: string;
      OwnerAccountId: string;
      "ProposedSegmentChange.AttachmentPolicyRuleNumber": number;
      "ProposedSegmentChange.SegmentName": string;
      "ProposedSegmentChange.Tags": Tag[];
      ResourceArn: string;
      SegmentName: string;
      State: string;
      UpdatedAt: string;
    }
    export interface ConnectAttachmentOptions {
      Protocol?: string;
    }
    export interface ProposedSegmentChange {
      AttachmentPolicyRuleNumber?: number;
      SegmentName?: string;
      Tags?: Tag[];
    }
  }
  export interface ConnectPeer {
    BgpOptions?: ConnectPeer.BgpOptions;
    ConnectAttachmentId?: string;
    CoreNetworkAddress?: string;
    InsideCidrBlocks?: string[];
    PeerAddress?: string;
    Tags?: Tag[];
  }
  export namespace ConnectPeer {
    export interface Attr {
      "Configuration.BgpConfigurations": ConnectPeerBgpConfiguration[];
      "Configuration.CoreNetworkAddress": string;
      "Configuration.InsideCidrBlocks": string[];
      "Configuration.PeerAddress": string;
      "Configuration.Protocol": string;
      ConnectPeerId: string;
      CoreNetworkId: string;
      CreatedAt: string;
      EdgeLocation: string;
      State: string;
    }
    export interface BgpOptions {
      PeerAsn?: number;
    }
    export interface ConnectPeerBgpConfiguration {
      CoreNetworkAddress?: string;
      CoreNetworkAsn?: number;
      PeerAddress?: string;
      PeerAsn?: number;
    }
    export interface ConnectPeerConfiguration {
      BgpConfigurations?: ConnectPeerBgpConfiguration[];
      CoreNetworkAddress?: string;
      InsideCidrBlocks?: string[];
      PeerAddress?: string;
      Protocol?: string;
    }
  }
  export interface CoreNetwork {
    Description?: string;
    GlobalNetworkId: string;
    PolicyDocument?: any;
    Tags?: Tag[];
  }
  export namespace CoreNetwork {
    export interface Attr {
      CoreNetworkArn: string;
      CoreNetworkId: string;
      CreatedAt: string;
      Edges: CoreNetworkEdge[];
      OwnerAccount: string;
      Segments: CoreNetworkSegment[];
      State: string;
    }
    export interface CoreNetworkEdge {
      Asn?: number;
      EdgeLocation?: string;
      InsideCidrBlocks?: string[];
    }
    export interface CoreNetworkSegment {
      EdgeLocations?: string[];
      Name?: string;
      SharedSegments?: string[];
    }
  }
  export interface CustomerGatewayAssociation {
    CustomerGatewayArn: string;
    DeviceId: string;
    GlobalNetworkId: string;
    LinkId?: string;
  }
  export interface Device {
    Description?: string;
    GlobalNetworkId: string;
    Location?: Device.Location;
    Model?: string;
    SerialNumber?: string;
    SiteId?: string;
    Tags?: Tag[];
    Type?: string;
    Vendor?: string;
  }
  export namespace Device {
    export interface Attr {
      DeviceArn: string;
      DeviceId: string;
    }
    export interface Location {
      Address?: string;
      Latitude?: string;
      Longitude?: string;
    }
  }
  export interface GlobalNetwork {
    Description?: string;
    Tags?: Tag[];
  }
  export interface Link {
    Bandwidth: Link.Bandwidth;
    Description?: string;
    GlobalNetworkId: string;
    Provider?: string;
    SiteId: string;
    Tags?: Tag[];
    Type?: string;
  }
  export namespace Link {
    export interface Attr {
      LinkArn: string;
      LinkId: string;
    }
    export interface Bandwidth {
      DownloadSpeed?: number;
      UploadSpeed?: number;
    }
  }
  export interface LinkAssociation {
    DeviceId: string;
    GlobalNetworkId: string;
    LinkId: string;
  }
  export interface Site {
    Description?: string;
    GlobalNetworkId: string;
    Location?: Site.Location;
    Tags?: Tag[];
  }
  export namespace Site {
    export interface Attr {
      SiteArn: string;
      SiteId: string;
    }
    export interface Location {
      Address?: string;
      Latitude?: string;
      Longitude?: string;
    }
  }
  export interface SiteToSiteVpnAttachment {
    CoreNetworkId?: string;
    Tags?: Tag[];
    VpnConnectionArn?: string;
  }
  export namespace SiteToSiteVpnAttachment {
    export interface Attr {
      AttachmentId: string;
      AttachmentPolicyRuleNumber: number;
      AttachmentType: string;
      CoreNetworkArn: string;
      CreatedAt: string;
      EdgeLocation: string;
      OwnerAccountId: string;
      "ProposedSegmentChange.AttachmentPolicyRuleNumber": number;
      "ProposedSegmentChange.SegmentName": string;
      "ProposedSegmentChange.Tags": Tag[];
      ResourceArn: string;
      SegmentName: string;
      State: string;
      UpdatedAt: string;
    }
    export interface ProposedSegmentChange {
      AttachmentPolicyRuleNumber?: number;
      SegmentName?: string;
      Tags?: Tag[];
    }
  }
  export interface TransitGatewayRegistration {
    GlobalNetworkId: string;
    TransitGatewayArn: string;
  }
  export interface VpcAttachment {
    CoreNetworkId: string;
    Options?: VpcAttachment.VpcOptions;
    SubnetArns: string[];
    Tags?: Tag[];
    VpcArn: string;
  }
  export namespace VpcAttachment {
    export interface Attr {
      AttachmentId: string;
      AttachmentPolicyRuleNumber: number;
      AttachmentType: string;
      CoreNetworkArn: string;
      CreatedAt: string;
      EdgeLocation: string;
      OwnerAccountId: string;
      "ProposedSegmentChange.AttachmentPolicyRuleNumber": number;
      "ProposedSegmentChange.SegmentName": string;
      "ProposedSegmentChange.Tags": Tag[];
      ResourceArn: string;
      SegmentName: string;
      State: string;
      UpdatedAt: string;
    }
    export interface ProposedSegmentChange {
      AttachmentPolicyRuleNumber?: number;
      SegmentName?: string;
      Tags?: Tag[];
    }
    export interface VpcOptions {
      ApplianceModeSupport?: boolean;
      Ipv6Support?: boolean;
    }
  }
}
export namespace NimbleStudio {
  export interface LaunchProfile {
    Description?: string;
    Ec2SubnetIds: string[];
    LaunchProfileProtocolVersions: string[];
    Name: string;
    StreamConfiguration: LaunchProfile.StreamConfiguration;
    StudioComponentIds: string[];
    StudioId: string;
    Tags?: Record<string, string>;
  }
  export namespace LaunchProfile {
    export interface Attr {
      LaunchProfileId: string;
    }
    export interface StreamConfiguration {
      AutomaticTerminationMode?: string;
      ClipboardMode: string;
      Ec2InstanceTypes: string[];
      MaxSessionLengthInMinutes?: number;
      MaxStoppedSessionLengthInMinutes?: number;
      SessionPersistenceMode?: string;
      SessionStorage?: StreamConfigurationSessionStorage;
      StreamingImageIds: string[];
      VolumeConfiguration?: VolumeConfiguration;
    }
    export interface StreamConfigurationSessionStorage {
      Mode: string[];
      Root?: StreamingSessionStorageRoot;
    }
    export interface StreamingSessionStorageRoot {
      Linux?: string;
      Windows?: string;
    }
    export interface VolumeConfiguration {
      Iops?: number;
      Size?: number;
      Throughput?: number;
    }
  }
  export interface StreamingImage {
    Description?: string;
    Ec2ImageId: string;
    Name: string;
    StudioId: string;
    Tags?: Record<string, string>;
  }
  export namespace StreamingImage {
    export interface Attr {
      "EncryptionConfiguration.KeyArn": string;
      "EncryptionConfiguration.KeyType": string;
      EulaIds: string[];
      Owner: string;
      Platform: string;
      StreamingImageId: string;
    }
    export interface StreamingImageEncryptionConfiguration {
      KeyArn?: string;
      KeyType: string;
    }
  }
  export interface Studio {
    AdminRoleArn: string;
    DisplayName: string;
    StudioEncryptionConfiguration?: Studio.StudioEncryptionConfiguration;
    StudioName: string;
    Tags?: Record<string, string>;
    UserRoleArn: string;
  }
  export namespace Studio {
    export interface Attr {
      HomeRegion: string;
      SsoClientId: string;
      StudioId: string;
      StudioUrl: string;
    }
    export interface StudioEncryptionConfiguration {
      KeyArn?: string;
      KeyType: string;
    }
  }
  export interface StudioComponent {
    Configuration?: StudioComponent.StudioComponentConfiguration;
    Description?: string;
    Ec2SecurityGroupIds?: string[];
    InitializationScripts?: StudioComponent.StudioComponentInitializationScript[];
    Name: string;
    ScriptParameters?: StudioComponent.ScriptParameterKeyValue[];
    StudioId: string;
    Subtype?: string;
    Tags?: Record<string, string>;
    Type: string;
  }
  export namespace StudioComponent {
    export interface Attr {
      StudioComponentId: string;
    }
    export interface ActiveDirectoryComputerAttribute {
      Name?: string;
      Value?: string;
    }
    export interface ActiveDirectoryConfiguration {
      ComputerAttributes?: ActiveDirectoryComputerAttribute[];
      DirectoryId?: string;
      OrganizationalUnitDistinguishedName?: string;
    }
    export interface ComputeFarmConfiguration {
      ActiveDirectoryUser?: string;
      Endpoint?: string;
    }
    export interface LicenseServiceConfiguration {
      Endpoint?: string;
    }
    export interface ScriptParameterKeyValue {
      Key?: string;
      Value?: string;
    }
    export interface SharedFileSystemConfiguration {
      Endpoint?: string;
      FileSystemId?: string;
      LinuxMountPoint?: string;
      ShareName?: string;
      WindowsMountDrive?: string;
    }
    export interface StudioComponentConfiguration {
      ActiveDirectoryConfiguration?: ActiveDirectoryConfiguration;
      ComputeFarmConfiguration?: ComputeFarmConfiguration;
      LicenseServiceConfiguration?: LicenseServiceConfiguration;
      SharedFileSystemConfiguration?: SharedFileSystemConfiguration;
    }
    export interface StudioComponentInitializationScript {
      LaunchProfileProtocolVersion?: string;
      Platform?: string;
      RunContext?: string;
      Script?: string;
    }
  }
}
export namespace Oam {
  export interface Link {
    LabelTemplate: string;
    ResourceTypes: string[];
    SinkIdentifier: string;
    Tags?: Record<string, string>;
  }
  export interface Sink {
    Name: string;
    Policy?: any;
    Tags?: Record<string, string>;
  }
}
export namespace OpenSearchServerless {
  export interface AccessPolicy {
    Description?: string;
    Name?: string;
    Policy?: string;
    Type?: string;
  }
  export interface Collection {
    Description?: string;
    Name: string;
    Tags?: Tag[];
    Type?: string;
  }
  export interface SecurityConfig {
    Description?: string;
    Name?: string;
    SamlOptions?: SecurityConfig.SamlConfigOptions;
    Type?: string;
  }
  export namespace SecurityConfig {
    export interface Attr {
      Id: string;
    }
    export interface SamlConfigOptions {
      GroupAttribute?: string;
      Metadata: string;
      SessionTimeout?: number;
      UserAttribute?: string;
    }
  }
  export interface SecurityPolicy {
    Description?: string;
    Name?: string;
    Policy: string;
    Type?: string;
  }
  export interface VpcEndpoint {
    Name: string;
    SecurityGroupIds?: string[];
    SubnetIds?: string[];
    VpcId: string;
  }
}
export namespace OpenSearchService {
  export interface Domain {
    AccessPolicies?: any;
    AdvancedOptions?: Record<string, string>;
    AdvancedSecurityOptions?: Domain.AdvancedSecurityOptionsInput;
    ClusterConfig?: Domain.ClusterConfig;
    CognitoOptions?: Domain.CognitoOptions;
    DomainEndpointOptions?: Domain.DomainEndpointOptions;
    DomainName?: string;
    EBSOptions?: Domain.EBSOptions;
    EncryptionAtRestOptions?: Domain.EncryptionAtRestOptions;
    EngineVersion?: string;
    LogPublishingOptions?: Record<string, Domain.LogPublishingOption>;
    NodeToNodeEncryptionOptions?: Domain.NodeToNodeEncryptionOptions;
    SnapshotOptions?: Domain.SnapshotOptions;
    Tags?: Tag[];
    VPCOptions?: Domain.VPCOptions;
  }
  export namespace Domain {
    export interface Attr {
      Arn: string;
      DomainEndpoint: string;
      DomainEndpoints: Record<string, string>;
      Id: string;
      "ServiceSoftwareOptions.AutomatedUpdateDate": string;
      "ServiceSoftwareOptions.Cancellable": boolean;
      "ServiceSoftwareOptions.CurrentVersion": string;
      "ServiceSoftwareOptions.Description": string;
      "ServiceSoftwareOptions.NewVersion": string;
      "ServiceSoftwareOptions.OptionalDeployment": boolean;
      "ServiceSoftwareOptions.UpdateAvailable": boolean;
      "ServiceSoftwareOptions.UpdateStatus": string;
    }
    export interface AdvancedSecurityOptionsInput {
      Enabled?: boolean;
      InternalUserDatabaseEnabled?: boolean;
      MasterUserOptions?: MasterUserOptions;
    }
    export interface ClusterConfig {
      DedicatedMasterCount?: number;
      DedicatedMasterEnabled?: boolean;
      DedicatedMasterType?: string;
      InstanceCount?: number;
      InstanceType?: string;
      WarmCount?: number;
      WarmEnabled?: boolean;
      WarmType?: string;
      ZoneAwarenessConfig?: ZoneAwarenessConfig;
      ZoneAwarenessEnabled?: boolean;
    }
    export interface CognitoOptions {
      Enabled?: boolean;
      IdentityPoolId?: string;
      RoleArn?: string;
      UserPoolId?: string;
    }
    export interface DomainEndpointOptions {
      CustomEndpoint?: string;
      CustomEndpointCertificateArn?: string;
      CustomEndpointEnabled?: boolean;
      EnforceHTTPS?: boolean;
      TLSSecurityPolicy?: string;
    }
    export interface EBSOptions {
      EBSEnabled?: boolean;
      Iops?: number;
      Throughput?: number;
      VolumeSize?: number;
      VolumeType?: string;
    }
    export interface EncryptionAtRestOptions {
      Enabled?: boolean;
      KmsKeyId?: string;
    }
    export interface LogPublishingOption {
      CloudWatchLogsLogGroupArn?: string;
      Enabled?: boolean;
    }
    export interface MasterUserOptions {
      MasterUserARN?: string;
      MasterUserName?: string;
      MasterUserPassword?: string;
    }
    export interface NodeToNodeEncryptionOptions {
      Enabled?: boolean;
    }
    export interface ServiceSoftwareOptions {
      AutomatedUpdateDate?: string;
      Cancellable?: boolean;
      CurrentVersion?: string;
      Description?: string;
      NewVersion?: string;
      OptionalDeployment?: boolean;
      UpdateAvailable?: boolean;
      UpdateStatus?: string;
    }
    export interface SnapshotOptions {
      AutomatedSnapshotStartHour?: number;
    }
    export interface VPCOptions {
      SecurityGroupIds?: string[];
      SubnetIds?: string[];
    }
    export interface ZoneAwarenessConfig {
      AvailabilityZoneCount?: number;
    }
  }
}
export namespace OpsWorks {
  export interface App {
    AppSource?: App.Source;
    Attributes?: Record<string, string>;
    DataSources?: App.DataSource[];
    Description?: string;
    Domains?: string[];
    EnableSsl?: boolean;
    Environment?: App.EnvironmentVariable[];
    Name: string;
    Shortname?: string;
    SslConfiguration?: App.SslConfiguration;
    StackId: string;
    Type: string;
  }
  export namespace App {
    export interface Attr {}
    export interface DataSource {
      Arn?: string;
      DatabaseName?: string;
      Type?: string;
    }
    export interface EnvironmentVariable {
      Key: string;
      Secure?: boolean;
      Value: string;
    }
    export interface Source {
      Password?: string;
      Revision?: string;
      SshKey?: string;
      Type?: string;
      Url?: string;
      Username?: string;
    }
    export interface SslConfiguration {
      Certificate?: string;
      Chain?: string;
      PrivateKey?: string;
    }
  }
  export interface ElasticLoadBalancerAttachment {
    ElasticLoadBalancerName: string;
    LayerId: string;
  }
  export interface Instance {
    AgentVersion?: string;
    AmiId?: string;
    Architecture?: string;
    AutoScalingType?: string;
    AvailabilityZone?: string;
    BlockDeviceMappings?: Instance.BlockDeviceMapping[];
    EbsOptimized?: boolean;
    ElasticIps?: string[];
    Hostname?: string;
    InstallUpdatesOnBoot?: boolean;
    InstanceType: string;
    LayerIds: string[];
    Os?: string;
    RootDeviceType?: string;
    SshKeyName?: string;
    StackId: string;
    SubnetId?: string;
    Tenancy?: string;
    TimeBasedAutoScaling?: Instance.TimeBasedAutoScaling;
    VirtualizationType?: string;
    Volumes?: string[];
  }
  export namespace Instance {
    export interface Attr {
      AvailabilityZone: string;
      PrivateDnsName: string;
      PrivateIp: string;
      PublicDnsName: string;
      PublicIp: string;
    }
    export interface BlockDeviceMapping {
      DeviceName?: string;
      Ebs?: EbsBlockDevice;
      NoDevice?: string;
      VirtualName?: string;
    }
    export interface EbsBlockDevice {
      DeleteOnTermination?: boolean;
      Iops?: number;
      SnapshotId?: string;
      VolumeSize?: number;
      VolumeType?: string;
    }
    export interface TimeBasedAutoScaling {
      Friday?: Record<string, string>;
      Monday?: Record<string, string>;
      Saturday?: Record<string, string>;
      Sunday?: Record<string, string>;
      Thursday?: Record<string, string>;
      Tuesday?: Record<string, string>;
      Wednesday?: Record<string, string>;
    }
  }
  export interface Layer {
    Attributes?: Record<string, string>;
    AutoAssignElasticIps: boolean;
    AutoAssignPublicIps: boolean;
    CustomInstanceProfileArn?: string;
    CustomJson?: any;
    CustomRecipes?: Layer.Recipes;
    CustomSecurityGroupIds?: string[];
    EnableAutoHealing: boolean;
    InstallUpdatesOnBoot?: boolean;
    LifecycleEventConfiguration?: Layer.LifecycleEventConfiguration;
    LoadBasedAutoScaling?: Layer.LoadBasedAutoScaling;
    Name: string;
    Packages?: string[];
    Shortname: string;
    StackId: string;
    Tags?: Tag[];
    Type: string;
    UseEbsOptimizedInstances?: boolean;
    VolumeConfigurations?: Layer.VolumeConfiguration[];
  }
  export namespace Layer {
    export interface Attr {}
    export interface AutoScalingThresholds {
      CpuThreshold?: number;
      IgnoreMetricsTime?: number;
      InstanceCount?: number;
      LoadThreshold?: number;
      MemoryThreshold?: number;
      ThresholdsWaitTime?: number;
    }
    export interface LifecycleEventConfiguration {
      ShutdownEventConfiguration?: ShutdownEventConfiguration;
    }
    export interface LoadBasedAutoScaling {
      DownScaling?: AutoScalingThresholds;
      Enable?: boolean;
      UpScaling?: AutoScalingThresholds;
    }
    export interface Recipes {
      Configure?: string[];
      Deploy?: string[];
      Setup?: string[];
      Shutdown?: string[];
      Undeploy?: string[];
    }
    export interface ShutdownEventConfiguration {
      DelayUntilElbConnectionsDrained?: boolean;
      ExecutionTimeout?: number;
    }
    export interface VolumeConfiguration {
      Encrypted?: boolean;
      Iops?: number;
      MountPoint?: string;
      NumberOfDisks?: number;
      RaidLevel?: number;
      Size?: number;
      VolumeType?: string;
    }
  }
  export interface Stack {
    AgentVersion?: string;
    Attributes?: Record<string, string>;
    ChefConfiguration?: Stack.ChefConfiguration;
    CloneAppIds?: string[];
    ClonePermissions?: boolean;
    ConfigurationManager?: Stack.StackConfigurationManager;
    CustomCookbooksSource?: Stack.Source;
    CustomJson?: any;
    DefaultAvailabilityZone?: string;
    DefaultInstanceProfileArn: string;
    DefaultOs?: string;
    DefaultRootDeviceType?: string;
    DefaultSshKeyName?: string;
    DefaultSubnetId?: string;
    EcsClusterArn?: string;
    ElasticIps?: Stack.ElasticIp[];
    HostnameTheme?: string;
    Name: string;
    RdsDbInstances?: Stack.RdsDbInstance[];
    ServiceRoleArn: string;
    SourceStackId?: string;
    Tags?: Tag[];
    UseCustomCookbooks?: boolean;
    UseOpsworksSecurityGroups?: boolean;
    VpcId?: string;
  }
  export namespace Stack {
    export interface Attr {}
    export interface ChefConfiguration {
      BerkshelfVersion?: string;
      ManageBerkshelf?: boolean;
    }
    export interface ElasticIp {
      Ip: string;
      Name?: string;
    }
    export interface RdsDbInstance {
      DbPassword: string;
      DbUser: string;
      RdsDbInstanceArn: string;
    }
    export interface Source {
      Password?: string;
      Revision?: string;
      SshKey?: string;
      Type?: string;
      Url?: string;
      Username?: string;
    }
    export interface StackConfigurationManager {
      Name?: string;
      Version?: string;
    }
  }
  export interface UserProfile {
    AllowSelfManagement?: boolean;
    IamUserArn: string;
    SshPublicKey?: string;
    SshUsername?: string;
  }
  export interface Volume {
    Ec2VolumeId: string;
    MountPoint?: string;
    Name?: string;
    StackId: string;
  }
}
export namespace OpsWorksCM {
  export interface Server {
    AssociatePublicIpAddress?: boolean;
    BackupId?: string;
    BackupRetentionCount?: number;
    CustomCertificate?: string;
    CustomDomain?: string;
    CustomPrivateKey?: string;
    DisableAutomatedBackup?: boolean;
    Engine?: string;
    EngineAttributes?: Server.EngineAttribute[];
    EngineModel?: string;
    EngineVersion?: string;
    InstanceProfileArn: string;
    InstanceType: string;
    KeyPair?: string;
    PreferredBackupWindow?: string;
    PreferredMaintenanceWindow?: string;
    SecurityGroupIds?: string[];
    ServerName?: string;
    ServiceRoleArn: string;
    SubnetIds?: string[];
    Tags?: Tag[];
  }
  export namespace Server {
    export interface Attr {
      Arn: string;
      Endpoint: string;
      Id: string;
    }
    export interface EngineAttribute {
      Name?: string;
      Value?: string;
    }
  }
}
export namespace Organizations {
  export interface Account {
    AccountName: string;
    Email: string;
    ParentIds?: string[];
    RoleName?: string;
    Tags?: Tag[];
  }
  export interface OrganizationalUnit {
    Name: string;
    ParentId: string;
    Tags?: Tag[];
  }
  export interface Policy {
    Content: string;
    Description?: string;
    Name: string;
    Tags?: Tag[];
    TargetIds?: string[];
    Type: string;
  }
}
export namespace Panorama {
  export interface ApplicationInstance {
    ApplicationInstanceIdToReplace?: string;
    DefaultRuntimeContextDevice: string;
    Description?: string;
    DeviceId?: string;
    ManifestOverridesPayload?: ApplicationInstance.ManifestOverridesPayload;
    ManifestPayload: ApplicationInstance.ManifestPayload;
    Name?: string;
    RuntimeRoleArn?: string;
    StatusFilter?: string;
    Tags?: Tag[];
  }
  export namespace ApplicationInstance {
    export interface Attr {
      ApplicationInstanceId: string;
      Arn: string;
      CreatedTime: number;
      DefaultRuntimeContextDeviceName: string;
      HealthStatus: string;
      LastUpdatedTime: number;
      Status: string;
      StatusDescription: string;
    }
    export interface ManifestOverridesPayload {
      PayloadData?: string;
    }
    export interface ManifestPayload {
      PayloadData?: string;
    }
  }
  export interface Package {
    PackageName: string;
    StorageLocation?: Package.StorageLocation;
    Tags?: Tag[];
  }
  export namespace Package {
    export interface Attr {
      Arn: string;
      CreatedTime: number;
      PackageId: string;
      "StorageLocation.BinaryPrefixLocation": string;
      "StorageLocation.Bucket": string;
      "StorageLocation.GeneratedPrefixLocation": string;
      "StorageLocation.ManifestPrefixLocation": string;
      "StorageLocation.RepoPrefixLocation": string;
    }
    export interface StorageLocation {
      BinaryPrefixLocation?: string;
      Bucket?: string;
      GeneratedPrefixLocation?: string;
      ManifestPrefixLocation?: string;
      RepoPrefixLocation?: string;
    }
  }
  export interface PackageVersion {
    MarkLatest?: boolean;
    OwnerAccount?: string;
    PackageId: string;
    PackageVersion: string;
    PatchVersion: string;
    UpdatedLatestPatchVersion?: string;
  }
}
export namespace Personalize {
  export interface Dataset {
    DatasetGroupArn: string;
    DatasetImportJob?: Dataset.DatasetImportJob;
    DatasetType: string;
    Name: string;
    SchemaArn: string;
  }
  export namespace Dataset {
    export interface Attr {
      DatasetArn: string;
    }
    export interface DataSource {
      DataLocation?: string;
    }
    export interface DatasetImportJob {
      DataSource?: any;
      DatasetArn?: string;
      DatasetImportJobArn?: string;
      JobName?: string;
      RoleArn?: string;
    }
  }
  export interface DatasetGroup {
    Domain?: string;
    KmsKeyArn?: string;
    Name: string;
    RoleArn?: string;
  }
  export interface Schema {
    Domain?: string;
    Name: string;
    Schema: string;
  }
  export interface Solution {
    DatasetGroupArn: string;
    EventType?: string;
    Name: string;
    PerformAutoML?: boolean;
    PerformHPO?: boolean;
    RecipeArn?: string;
    SolutionConfig?: Solution.SolutionConfig;
  }
  export namespace Solution {
    export interface Attr {
      SolutionArn: string;
    }
    export interface AlgorithmHyperParameterRanges {
      CategoricalHyperParameterRanges?: CategoricalHyperParameterRange[];
      ContinuousHyperParameterRanges?: ContinuousHyperParameterRange[];
      IntegerHyperParameterRanges?: IntegerHyperParameterRange[];
    }
    export interface AutoMLConfig {
      MetricName?: string;
      RecipeList?: string[];
    }
    export interface CategoricalHyperParameterRange {
      Name?: string;
      Values?: string[];
    }
    export interface ContinuousHyperParameterRange {
      MaxValue?: number;
      MinValue?: number;
      Name?: string;
    }
    export interface HpoConfig {
      AlgorithmHyperParameterRanges?: AlgorithmHyperParameterRanges;
      HpoObjective?: HpoObjective;
      HpoResourceConfig?: HpoResourceConfig;
    }
    export interface HpoObjective {
      MetricName?: string;
      MetricRegex?: string;
      Type?: string;
    }
    export interface HpoResourceConfig {
      MaxNumberOfTrainingJobs?: string;
      MaxParallelTrainingJobs?: string;
    }
    export interface IntegerHyperParameterRange {
      MaxValue?: number;
      MinValue?: number;
      Name?: string;
    }
    export interface SolutionConfig {
      AlgorithmHyperParameters?: Record<string, string>;
      AutoMLConfig?: any;
      EventValueThreshold?: string;
      FeatureTransformationParameters?: Record<string, string>;
      HpoConfig?: any;
    }
  }
}
export namespace Pinpoint {
  export interface ADMChannel {
    ApplicationId: string;
    ClientId: string;
    ClientSecret: string;
    Enabled?: boolean;
  }
  export interface APNSChannel {
    ApplicationId: string;
    BundleId?: string;
    Certificate?: string;
    DefaultAuthenticationMethod?: string;
    Enabled?: boolean;
    PrivateKey?: string;
    TeamId?: string;
    TokenKey?: string;
    TokenKeyId?: string;
  }
  export interface APNSSandboxChannel {
    ApplicationId: string;
    BundleId?: string;
    Certificate?: string;
    DefaultAuthenticationMethod?: string;
    Enabled?: boolean;
    PrivateKey?: string;
    TeamId?: string;
    TokenKey?: string;
    TokenKeyId?: string;
  }
  export interface APNSVoipChannel {
    ApplicationId: string;
    BundleId?: string;
    Certificate?: string;
    DefaultAuthenticationMethod?: string;
    Enabled?: boolean;
    PrivateKey?: string;
    TeamId?: string;
    TokenKey?: string;
    TokenKeyId?: string;
  }
  export interface APNSVoipSandboxChannel {
    ApplicationId: string;
    BundleId?: string;
    Certificate?: string;
    DefaultAuthenticationMethod?: string;
    Enabled?: boolean;
    PrivateKey?: string;
    TeamId?: string;
    TokenKey?: string;
    TokenKeyId?: string;
  }
  export interface App {
    Name: string;
    Tags?: any;
  }
  export interface ApplicationSettings {
    ApplicationId: string;
    CampaignHook?: ApplicationSettings.CampaignHook;
    CloudWatchMetricsEnabled?: boolean;
    Limits?: ApplicationSettings.Limits;
    QuietTime?: ApplicationSettings.QuietTime;
  }
  export namespace ApplicationSettings {
    export interface Attr {}
    export interface CampaignHook {
      LambdaFunctionName?: string;
      Mode?: string;
      WebUrl?: string;
    }
    export interface Limits {
      Daily?: number;
      MaximumDuration?: number;
      MessagesPerSecond?: number;
      Total?: number;
    }
    export interface QuietTime {
      End: string;
      Start: string;
    }
  }
  export interface BaiduChannel {
    ApiKey: string;
    ApplicationId: string;
    Enabled?: boolean;
    SecretKey: string;
  }
  export interface Campaign {
    AdditionalTreatments?: Campaign.WriteTreatmentResource[];
    ApplicationId: string;
    CampaignHook?: Campaign.CampaignHook;
    CustomDeliveryConfiguration?: Campaign.CustomDeliveryConfiguration;
    Description?: string;
    HoldoutPercent?: number;
    IsPaused?: boolean;
    Limits?: Campaign.Limits;
    MessageConfiguration?: Campaign.MessageConfiguration;
    Name: string;
    Priority?: number;
    Schedule: Campaign.Schedule;
    SegmentId: string;
    SegmentVersion?: number;
    Tags?: any;
    TemplateConfiguration?: Campaign.TemplateConfiguration;
    TreatmentDescription?: string;
    TreatmentName?: string;
  }
  export namespace Campaign {
    export interface Attr {
      Arn: string;
      CampaignId: string;
    }
    export interface AttributeDimension {
      AttributeType?: string;
      Values?: string[];
    }
    export interface CampaignCustomMessage {
      Data?: string;
    }
    export interface CampaignEmailMessage {
      Body?: string;
      FromAddress?: string;
      HtmlBody?: string;
      Title?: string;
    }
    export interface CampaignEventFilter {
      Dimensions?: EventDimensions;
      FilterType?: string;
    }
    export interface CampaignHook {
      LambdaFunctionName?: string;
      Mode?: string;
      WebUrl?: string;
    }
    export interface CampaignInAppMessage {
      Content?: InAppMessageContent[];
      CustomConfig?: any;
      Layout?: string;
    }
    export interface CampaignSmsMessage {
      Body?: string;
      EntityId?: string;
      MessageType?: string;
      OriginationNumber?: string;
      SenderId?: string;
      TemplateId?: string;
    }
    export interface CustomDeliveryConfiguration {
      DeliveryUri?: string;
      EndpointTypes?: string[];
    }
    export interface DefaultButtonConfiguration {
      BackgroundColor?: string;
      BorderRadius?: number;
      ButtonAction?: string;
      Link?: string;
      Text?: string;
      TextColor?: string;
    }
    export interface EventDimensions {
      Attributes?: any;
      EventType?: SetDimension;
      Metrics?: any;
    }
    export interface InAppMessageBodyConfig {
      Alignment?: string;
      Body?: string;
      TextColor?: string;
    }
    export interface InAppMessageButton {
      Android?: OverrideButtonConfiguration;
      DefaultConfig?: DefaultButtonConfiguration;
      IOS?: OverrideButtonConfiguration;
      Web?: OverrideButtonConfiguration;
    }
    export interface InAppMessageContent {
      BackgroundColor?: string;
      BodyConfig?: InAppMessageBodyConfig;
      HeaderConfig?: InAppMessageHeaderConfig;
      ImageUrl?: string;
      PrimaryBtn?: InAppMessageButton;
      SecondaryBtn?: InAppMessageButton;
    }
    export interface InAppMessageHeaderConfig {
      Alignment?: string;
      Header?: string;
      TextColor?: string;
    }
    export interface Limits {
      Daily?: number;
      MaximumDuration?: number;
      MessagesPerSecond?: number;
      Session?: number;
      Total?: number;
    }
    export interface Message {
      Action?: string;
      Body?: string;
      ImageIconUrl?: string;
      ImageSmallIconUrl?: string;
      ImageUrl?: string;
      JsonBody?: string;
      MediaUrl?: string;
      RawContent?: string;
      SilentPush?: boolean;
      TimeToLive?: number;
      Title?: string;
      Url?: string;
    }
    export interface MessageConfiguration {
      ADMMessage?: Message;
      APNSMessage?: Message;
      BaiduMessage?: Message;
      CustomMessage?: CampaignCustomMessage;
      DefaultMessage?: Message;
      EmailMessage?: CampaignEmailMessage;
      GCMMessage?: Message;
      InAppMessage?: CampaignInAppMessage;
      SMSMessage?: CampaignSmsMessage;
    }
    export interface MetricDimension {
      ComparisonOperator?: string;
      Value?: number;
    }
    export interface OverrideButtonConfiguration {
      ButtonAction?: string;
      Link?: string;
    }
    export interface QuietTime {
      End: string;
      Start: string;
    }
    export interface Schedule {
      EndTime?: string;
      EventFilter?: CampaignEventFilter;
      Frequency?: string;
      IsLocalTime?: boolean;
      QuietTime?: QuietTime;
      StartTime?: string;
      TimeZone?: string;
    }
    export interface SetDimension {
      DimensionType?: string;
      Values?: string[];
    }
    export interface Template {
      Name?: string;
      Version?: string;
    }
    export interface TemplateConfiguration {
      EmailTemplate?: Template;
      PushTemplate?: Template;
      SMSTemplate?: Template;
      VoiceTemplate?: Template;
    }
    export interface WriteTreatmentResource {
      CustomDeliveryConfiguration?: CustomDeliveryConfiguration;
      MessageConfiguration?: MessageConfiguration;
      Schedule?: Schedule;
      SizePercent?: number;
      TemplateConfiguration?: TemplateConfiguration;
      TreatmentDescription?: string;
      TreatmentName?: string;
    }
  }
  export interface EmailChannel {
    ApplicationId: string;
    ConfigurationSet?: string;
    Enabled?: boolean;
    FromAddress: string;
    Identity: string;
    RoleArn?: string;
  }
  export interface EmailTemplate {
    DefaultSubstitutions?: string;
    HtmlPart?: string;
    Subject: string;
    Tags?: any;
    TemplateDescription?: string;
    TemplateName: string;
    TextPart?: string;
  }
  export interface EventStream {
    ApplicationId: string;
    DestinationStreamArn: string;
    RoleArn: string;
  }
  export interface GCMChannel {
    ApiKey: string;
    ApplicationId: string;
    Enabled?: boolean;
  }
  export interface InAppTemplate {
    Content?: InAppTemplate.InAppMessageContent[];
    CustomConfig?: any;
    Layout?: string;
    Tags?: any;
    TemplateDescription?: string;
    TemplateName: string;
  }
  export namespace InAppTemplate {
    export interface Attr {
      Arn: string;
    }
    export interface BodyConfig {
      Alignment?: string;
      Body?: string;
      TextColor?: string;
    }
    export interface ButtonConfig {
      Android?: OverrideButtonConfiguration;
      DefaultConfig?: DefaultButtonConfiguration;
      IOS?: OverrideButtonConfiguration;
      Web?: OverrideButtonConfiguration;
    }
    export interface DefaultButtonConfiguration {
      BackgroundColor?: string;
      BorderRadius?: number;
      ButtonAction?: string;
      Link?: string;
      Text?: string;
      TextColor?: string;
    }
    export interface HeaderConfig {
      Alignment?: string;
      Header?: string;
      TextColor?: string;
    }
    export interface InAppMessageContent {
      BackgroundColor?: string;
      BodyConfig?: BodyConfig;
      HeaderConfig?: HeaderConfig;
      ImageUrl?: string;
      PrimaryBtn?: ButtonConfig;
      SecondaryBtn?: ButtonConfig;
    }
    export interface OverrideButtonConfiguration {
      ButtonAction?: string;
      Link?: string;
    }
  }
  export interface PushTemplate {
    ADM?: PushTemplate.AndroidPushNotificationTemplate;
    APNS?: PushTemplate.APNSPushNotificationTemplate;
    Baidu?: PushTemplate.AndroidPushNotificationTemplate;
    Default?: PushTemplate.DefaultPushNotificationTemplate;
    DefaultSubstitutions?: string;
    GCM?: PushTemplate.AndroidPushNotificationTemplate;
    Tags?: any;
    TemplateDescription?: string;
    TemplateName: string;
  }
  export namespace PushTemplate {
    export interface Attr {
      Arn: string;
    }
    export interface APNSPushNotificationTemplate {
      Action?: string;
      Body?: string;
      MediaUrl?: string;
      Sound?: string;
      Title?: string;
      Url?: string;
    }
    export interface AndroidPushNotificationTemplate {
      Action?: string;
      Body?: string;
      ImageIconUrl?: string;
      ImageUrl?: string;
      SmallImageIconUrl?: string;
      Sound?: string;
      Title?: string;
      Url?: string;
    }
    export interface DefaultPushNotificationTemplate {
      Action?: string;
      Body?: string;
      Sound?: string;
      Title?: string;
      Url?: string;
    }
  }
  export interface SMSChannel {
    ApplicationId: string;
    Enabled?: boolean;
    SenderId?: string;
    ShortCode?: string;
  }
  export interface Segment {
    ApplicationId: string;
    Dimensions?: Segment.SegmentDimensions;
    Name: string;
    SegmentGroups?: Segment.SegmentGroups;
    Tags?: any;
  }
  export namespace Segment {
    export interface Attr {
      Arn: string;
      SegmentId: string;
    }
    export interface AttributeDimension {
      AttributeType?: string;
      Values?: string[];
    }
    export interface Behavior {
      Recency?: Recency;
    }
    export interface Coordinates {
      Latitude: number;
      Longitude: number;
    }
    export interface Demographic {
      AppVersion?: SetDimension;
      Channel?: SetDimension;
      DeviceType?: SetDimension;
      Make?: SetDimension;
      Model?: SetDimension;
      Platform?: SetDimension;
    }
    export interface GPSPoint {
      Coordinates: Coordinates;
      RangeInKilometers: number;
    }
    export interface Groups {
      Dimensions?: SegmentDimensions[];
      SourceSegments?: SourceSegments[];
      SourceType?: string;
      Type?: string;
    }
    export interface Location {
      Country?: SetDimension;
      GPSPoint?: GPSPoint;
    }
    export interface Recency {
      Duration: string;
      RecencyType: string;
    }
    export interface SegmentDimensions {
      Attributes?: any;
      Behavior?: Behavior;
      Demographic?: Demographic;
      Location?: Location;
      Metrics?: any;
      UserAttributes?: any;
    }
    export interface SegmentGroups {
      Groups?: Groups[];
      Include?: string;
    }
    export interface SetDimension {
      DimensionType?: string;
      Values?: string[];
    }
    export interface SourceSegments {
      Id: string;
      Version?: number;
    }
  }
  export interface SmsTemplate {
    Body: string;
    DefaultSubstitutions?: string;
    Tags?: any;
    TemplateDescription?: string;
    TemplateName: string;
  }
  export interface VoiceChannel {
    ApplicationId: string;
    Enabled?: boolean;
  }
}
export namespace PinpointEmail {
  export interface ConfigurationSet {
    DeliveryOptions?: ConfigurationSet.DeliveryOptions;
    Name: string;
    ReputationOptions?: ConfigurationSet.ReputationOptions;
    SendingOptions?: ConfigurationSet.SendingOptions;
    Tags?: ConfigurationSet.Tags[];
    TrackingOptions?: ConfigurationSet.TrackingOptions;
  }
  export namespace ConfigurationSet {
    export interface Attr {}
    export interface DeliveryOptions {
      SendingPoolName?: string;
    }
    export interface ReputationOptions {
      ReputationMetricsEnabled?: boolean;
    }
    export interface SendingOptions {
      SendingEnabled?: boolean;
    }
    export interface Tags {
      Key?: string;
      Value?: string;
    }
    export interface TrackingOptions {
      CustomRedirectDomain?: string;
    }
  }
  export interface ConfigurationSetEventDestination {
    ConfigurationSetName: string;
    EventDestination?: ConfigurationSetEventDestination.EventDestination;
    EventDestinationName: string;
  }
  export namespace ConfigurationSetEventDestination {
    export interface Attr {}
    export interface CloudWatchDestination {
      DimensionConfigurations?: DimensionConfiguration[];
    }
    export interface DimensionConfiguration {
      DefaultDimensionValue: string;
      DimensionName: string;
      DimensionValueSource: string;
    }
    export interface EventDestination {
      CloudWatchDestination?: CloudWatchDestination;
      Enabled?: boolean;
      KinesisFirehoseDestination?: KinesisFirehoseDestination;
      MatchingEventTypes: string[];
      PinpointDestination?: PinpointDestination;
      SnsDestination?: SnsDestination;
    }
    export interface KinesisFirehoseDestination {
      DeliveryStreamArn: string;
      IamRoleArn: string;
    }
    export interface PinpointDestination {
      ApplicationArn?: string;
    }
    export interface SnsDestination {
      TopicArn: string;
    }
  }
  export interface DedicatedIpPool {
    PoolName?: string;
    Tags?: DedicatedIpPool.Tags[];
  }
  export namespace DedicatedIpPool {
    export interface Attr {}
    export interface Tags {
      Key?: string;
      Value?: string;
    }
  }
  export interface Identity {
    DkimSigningEnabled?: boolean;
    FeedbackForwardingEnabled?: boolean;
    MailFromAttributes?: Identity.MailFromAttributes;
    Name: string;
    Tags?: Identity.Tags[];
  }
  export namespace Identity {
    export interface Attr {
      IdentityDNSRecordName1: string;
      IdentityDNSRecordName2: string;
      IdentityDNSRecordName3: string;
      IdentityDNSRecordValue1: string;
      IdentityDNSRecordValue2: string;
      IdentityDNSRecordValue3: string;
    }
    export interface MailFromAttributes {
      BehaviorOnMxFailure?: string;
      MailFromDomain?: string;
    }
    export interface Tags {
      Key?: string;
      Value?: string;
    }
  }
}
export namespace Pipes {
  export interface Pipe {
    Description?: string;
    DesiredState?: string;
    Enrichment?: string;
    EnrichmentParameters?: Pipe.PipeEnrichmentParameters;
    Name?: string;
    RoleArn: string;
    Source: string;
    SourceParameters?: Pipe.PipeSourceParameters;
    Tags?: Record<string, string>;
    Target: string;
    TargetParameters?: Pipe.PipeTargetParameters;
  }
  export namespace Pipe {
    export interface Attr {
      Arn: string;
      CreationTime: string;
      CurrentState: string;
      LastModifiedTime: string;
      StateReason: string;
    }
    export interface AwsVpcConfiguration {
      AssignPublicIp?: string;
      SecurityGroups?: string[];
      Subnets: string[];
    }
    export interface BatchArrayProperties {
      Size?: number;
    }
    export interface BatchContainerOverrides {
      Command?: string[];
      Environment?: BatchEnvironmentVariable[];
      InstanceType?: string;
      ResourceRequirements?: BatchResourceRequirement[];
    }
    export interface BatchEnvironmentVariable {
      Name?: string;
      Value?: string;
    }
    export interface BatchJobDependency {
      JobId?: string;
      Type?: string;
    }
    export interface BatchResourceRequirement {
      Type: string;
      Value: string;
    }
    export interface BatchRetryStrategy {
      Attempts?: number;
    }
    export interface CapacityProviderStrategyItem {
      Base?: number;
      CapacityProvider: string;
      Weight?: number;
    }
    export interface DeadLetterConfig {
      Arn?: string;
    }
    export interface EcsContainerOverride {
      Command?: string[];
      Cpu?: number;
      Environment?: EcsEnvironmentVariable[];
      EnvironmentFiles?: EcsEnvironmentFile[];
      Memory?: number;
      MemoryReservation?: number;
      Name?: string;
      ResourceRequirements?: EcsResourceRequirement[];
    }
    export interface EcsEnvironmentFile {
      Type: string;
      Value: string;
    }
    export interface EcsEnvironmentVariable {
      Name?: string;
      Value?: string;
    }
    export interface EcsEphemeralStorage {
      SizeInGiB: number;
    }
    export interface EcsInferenceAcceleratorOverride {
      DeviceName?: string;
      DeviceType?: string;
    }
    export interface EcsResourceRequirement {
      Type: string;
      Value: string;
    }
    export interface EcsTaskOverride {
      ContainerOverrides?: EcsContainerOverride[];
      Cpu?: string;
      EphemeralStorage?: EcsEphemeralStorage;
      ExecutionRoleArn?: string;
      InferenceAcceleratorOverrides?: EcsInferenceAcceleratorOverride[];
      Memory?: string;
      TaskRoleArn?: string;
    }
    export interface Filter {
      Pattern?: string;
    }
    export interface FilterCriteria {
      Filters?: Filter[];
    }
    export interface MQBrokerAccessCredentials {
      BasicAuth: string;
    }
    export interface MSKAccessCredentials {
      ClientCertificateTlsAuth?: string;
      SaslScram512Auth?: string;
    }
    export interface NetworkConfiguration {
      AwsvpcConfiguration?: AwsVpcConfiguration;
    }
    export interface PipeEnrichmentHttpParameters {
      HeaderParameters?: Record<string, string>;
      PathParameterValues?: string[];
      QueryStringParameters?: Record<string, string>;
    }
    export interface PipeEnrichmentParameters {
      HttpParameters?: PipeEnrichmentHttpParameters;
      InputTemplate?: string;
    }
    export interface PipeSourceActiveMQBrokerParameters {
      BatchSize?: number;
      Credentials: MQBrokerAccessCredentials;
      MaximumBatchingWindowInSeconds?: number;
      QueueName: string;
    }
    export interface PipeSourceDynamoDBStreamParameters {
      BatchSize?: number;
      DeadLetterConfig?: DeadLetterConfig;
      MaximumBatchingWindowInSeconds?: number;
      MaximumRecordAgeInSeconds?: number;
      MaximumRetryAttempts?: number;
      OnPartialBatchItemFailure?: string;
      ParallelizationFactor?: number;
      StartingPosition: string;
    }
    export interface PipeSourceKinesisStreamParameters {
      BatchSize?: number;
      DeadLetterConfig?: DeadLetterConfig;
      MaximumBatchingWindowInSeconds?: number;
      MaximumRecordAgeInSeconds?: number;
      MaximumRetryAttempts?: number;
      OnPartialBatchItemFailure?: string;
      ParallelizationFactor?: number;
      StartingPosition: string;
      StartingPositionTimestamp?: string;
    }
    export interface PipeSourceManagedStreamingKafkaParameters {
      BatchSize?: number;
      ConsumerGroupID?: string;
      Credentials?: MSKAccessCredentials;
      MaximumBatchingWindowInSeconds?: number;
      StartingPosition?: string;
      TopicName: string;
    }
    export interface PipeSourceParameters {
      ActiveMQBrokerParameters?: PipeSourceActiveMQBrokerParameters;
      DynamoDBStreamParameters?: PipeSourceDynamoDBStreamParameters;
      FilterCriteria?: FilterCriteria;
      KinesisStreamParameters?: PipeSourceKinesisStreamParameters;
      ManagedStreamingKafkaParameters?: PipeSourceManagedStreamingKafkaParameters;
      RabbitMQBrokerParameters?: PipeSourceRabbitMQBrokerParameters;
      SelfManagedKafkaParameters?: PipeSourceSelfManagedKafkaParameters;
      SqsQueueParameters?: PipeSourceSqsQueueParameters;
    }
    export interface PipeSourceRabbitMQBrokerParameters {
      BatchSize?: number;
      Credentials: MQBrokerAccessCredentials;
      MaximumBatchingWindowInSeconds?: number;
      QueueName: string;
      VirtualHost?: string;
    }
    export interface PipeSourceSelfManagedKafkaParameters {
      AdditionalBootstrapServers?: string[];
      BatchSize?: number;
      ConsumerGroupID?: string;
      Credentials?: SelfManagedKafkaAccessConfigurationCredentials;
      MaximumBatchingWindowInSeconds?: number;
      ServerRootCaCertificate?: string;
      StartingPosition?: string;
      TopicName: string;
      Vpc?: SelfManagedKafkaAccessConfigurationVpc;
    }
    export interface PipeSourceSqsQueueParameters {
      BatchSize?: number;
      MaximumBatchingWindowInSeconds?: number;
    }
    export interface PipeTargetBatchJobParameters {
      ArrayProperties?: BatchArrayProperties;
      ContainerOverrides?: BatchContainerOverrides;
      DependsOn?: BatchJobDependency[];
      JobDefinition: string;
      JobName: string;
      Parameters?: Record<string, string>;
      RetryStrategy?: BatchRetryStrategy;
    }
    export interface PipeTargetCloudWatchLogsParameters {
      LogStreamName?: string;
      Timestamp?: string;
    }
    export interface PipeTargetEcsTaskParameters {
      CapacityProviderStrategy?: CapacityProviderStrategyItem[];
      EnableECSManagedTags?: boolean;
      EnableExecuteCommand?: boolean;
      Group?: string;
      LaunchType?: string;
      NetworkConfiguration?: NetworkConfiguration;
      Overrides?: EcsTaskOverride;
      PlacementConstraints?: PlacementConstraint[];
      PlacementStrategy?: PlacementStrategy[];
      PlatformVersion?: string;
      PropagateTags?: string;
      ReferenceId?: string;
      Tags?: Tag[];
      TaskCount?: number;
      TaskDefinitionArn: string;
    }
    export interface PipeTargetEventBridgeEventBusParameters {
      DetailType?: string;
      EndpointId?: string;
      Resources?: string[];
      Source?: string;
      Time?: string;
    }
    export interface PipeTargetHttpParameters {
      HeaderParameters?: Record<string, string>;
      PathParameterValues?: string[];
      QueryStringParameters?: Record<string, string>;
    }
    export interface PipeTargetKinesisStreamParameters {
      PartitionKey: string;
    }
    export interface PipeTargetLambdaFunctionParameters {
      InvocationType?: string;
    }
    export interface PipeTargetParameters {
      BatchJobParameters?: PipeTargetBatchJobParameters;
      CloudWatchLogsParameters?: PipeTargetCloudWatchLogsParameters;
      EcsTaskParameters?: PipeTargetEcsTaskParameters;
      EventBridgeEventBusParameters?: PipeTargetEventBridgeEventBusParameters;
      HttpParameters?: PipeTargetHttpParameters;
      InputTemplate?: string;
      KinesisStreamParameters?: PipeTargetKinesisStreamParameters;
      LambdaFunctionParameters?: PipeTargetLambdaFunctionParameters;
      RedshiftDataParameters?: PipeTargetRedshiftDataParameters;
      SageMakerPipelineParameters?: PipeTargetSageMakerPipelineParameters;
      SqsQueueParameters?: PipeTargetSqsQueueParameters;
      StepFunctionStateMachineParameters?: PipeTargetStateMachineParameters;
    }
    export interface PipeTargetRedshiftDataParameters {
      Database: string;
      DbUser?: string;
      SecretManagerArn?: string;
      Sqls: string[];
      StatementName?: string;
      WithEvent?: boolean;
    }
    export interface PipeTargetSageMakerPipelineParameters {
      PipelineParameterList?: SageMakerPipelineParameter[];
    }
    export interface PipeTargetSqsQueueParameters {
      MessageDeduplicationId?: string;
      MessageGroupId?: string;
    }
    export interface PipeTargetStateMachineParameters {
      InvocationType?: string;
    }
    export interface PlacementConstraint {
      Expression?: string;
      Type?: string;
    }
    export interface PlacementStrategy {
      Field?: string;
      Type?: string;
    }
    export interface SageMakerPipelineParameter {
      Name: string;
      Value: string;
    }
    export interface SelfManagedKafkaAccessConfigurationCredentials {
      BasicAuth?: string;
      ClientCertificateTlsAuth?: string;
      SaslScram256Auth?: string;
      SaslScram512Auth?: string;
    }
    export interface SelfManagedKafkaAccessConfigurationVpc {
      SecurityGroup?: string[];
      Subnets?: string[];
    }
  }
}
export namespace QLDB {
  export interface Ledger {
    DeletionProtection?: boolean;
    KmsKey?: string;
    Name?: string;
    PermissionsMode: string;
    Tags?: Tag[];
  }
  export interface Stream {
    ExclusiveEndTime?: string;
    InclusiveStartTime: string;
    KinesisConfiguration: Stream.KinesisConfiguration;
    LedgerName: string;
    RoleArn: string;
    StreamName: string;
    Tags?: Tag[];
  }
  export namespace Stream {
    export interface Attr {
      Arn: string;
      Id: string;
    }
    export interface KinesisConfiguration {
      AggregationEnabled?: boolean;
      StreamArn?: string;
    }
  }
}
export namespace QuickSight {
  export interface Analysis {
    AnalysisId: string;
    AwsAccountId: string;
    Errors?: Analysis.AnalysisError[];
    Name?: string;
    Parameters?: Analysis.Parameters;
    Permissions?: Analysis.ResourcePermission[];
    SourceEntity: Analysis.AnalysisSourceEntity;
    Tags?: Tag[];
    ThemeArn?: string;
  }
  export namespace Analysis {
    export interface Attr {
      Arn: string;
      CreatedTime: string;
      DataSetArns: string[];
      LastUpdatedTime: string;
      Sheets: Sheet[];
      Status: string;
    }
    export interface AnalysisError {
      Message?: string;
      Type?: string;
    }
    export interface AnalysisSourceEntity {
      SourceTemplate?: AnalysisSourceTemplate;
    }
    export interface AnalysisSourceTemplate {
      Arn: string;
      DataSetReferences: DataSetReference[];
    }
    export interface DataSetReference {
      DataSetArn: string;
      DataSetPlaceholder: string;
    }
    export interface DateTimeParameter {
      Name: string;
      Values: string[];
    }
    export interface DecimalParameter {
      Name: string;
      Values: number[];
    }
    export interface IntegerParameter {
      Name: string;
      Values: number[];
    }
    export interface Parameters {
      DateTimeParameters?: DateTimeParameter[];
      DecimalParameters?: DecimalParameter[];
      IntegerParameters?: IntegerParameter[];
      StringParameters?: StringParameter[];
    }
    export interface ResourcePermission {
      Actions: string[];
      Principal: string;
    }
    export interface Sheet {
      Name?: string;
      SheetId?: string;
    }
    export interface StringParameter {
      Name: string;
      Values: string[];
    }
  }
  export interface Dashboard {
    AwsAccountId: string;
    DashboardId: string;
    DashboardPublishOptions?: Dashboard.DashboardPublishOptions;
    Name?: string;
    Parameters?: Dashboard.Parameters;
    Permissions?: Dashboard.ResourcePermission[];
    SourceEntity: Dashboard.DashboardSourceEntity;
    Tags?: Tag[];
    ThemeArn?: string;
    VersionDescription?: string;
  }
  export namespace Dashboard {
    export interface Attr {
      Arn: string;
      CreatedTime: string;
      LastPublishedTime: string;
      LastUpdatedTime: string;
      "Version.Arn": string;
      "Version.CreatedTime": string;
      "Version.DataSetArns": string[];
      "Version.Description": string;
      "Version.Errors": DashboardError[];
      "Version.Sheets": Sheet[];
      "Version.SourceEntityArn": string;
      "Version.Status": string;
      "Version.ThemeArn": string;
      "Version.VersionNumber": number;
    }
    export interface AdHocFilteringOption {
      AvailabilityStatus?: string;
    }
    export interface DashboardError {
      Message?: string;
      Type?: string;
    }
    export interface DashboardPublishOptions {
      AdHocFilteringOption?: AdHocFilteringOption;
      ExportToCSVOption?: ExportToCSVOption;
      SheetControlsOption?: SheetControlsOption;
    }
    export interface DashboardSourceEntity {
      SourceTemplate?: DashboardSourceTemplate;
    }
    export interface DashboardSourceTemplate {
      Arn: string;
      DataSetReferences: DataSetReference[];
    }
    export interface DashboardVersion {
      Arn?: string;
      CreatedTime?: string;
      DataSetArns?: string[];
      Description?: string;
      Errors?: DashboardError[];
      Sheets?: Sheet[];
      SourceEntityArn?: string;
      Status?: string;
      ThemeArn?: string;
      VersionNumber?: number;
    }
    export interface DataSetReference {
      DataSetArn: string;
      DataSetPlaceholder: string;
    }
    export interface DateTimeParameter {
      Name: string;
      Values: string[];
    }
    export interface DecimalParameter {
      Name: string;
      Values: number[];
    }
    export interface ExportToCSVOption {
      AvailabilityStatus?: string;
    }
    export interface IntegerParameter {
      Name: string;
      Values: number[];
    }
    export interface Parameters {
      DateTimeParameters?: DateTimeParameter[];
      DecimalParameters?: DecimalParameter[];
      IntegerParameters?: IntegerParameter[];
      StringParameters?: StringParameter[];
    }
    export interface ResourcePermission {
      Actions: string[];
      Principal: string;
    }
    export interface Sheet {
      Name?: string;
      SheetId?: string;
    }
    export interface SheetControlsOption {
      VisibilityState?: string;
    }
    export interface StringParameter {
      Name: string;
      Values: string[];
    }
  }
  export interface DataSet {
    AwsAccountId?: string;
    ColumnGroups?: DataSet.ColumnGroup[];
    ColumnLevelPermissionRules?: DataSet.ColumnLevelPermissionRule[];
    DataSetId?: string;
    DataSetUsageConfiguration?: DataSet.DataSetUsageConfiguration;
    FieldFolders?: Record<string, DataSet.FieldFolder>;
    ImportMode?: string;
    IngestionWaitPolicy?: DataSet.IngestionWaitPolicy;
    LogicalTableMap?: Record<string, DataSet.LogicalTable>;
    Name?: string;
    Permissions?: DataSet.ResourcePermission[];
    PhysicalTableMap?: Record<string, DataSet.PhysicalTable>;
    RowLevelPermissionDataSet?: DataSet.RowLevelPermissionDataSet;
    Tags?: Tag[];
  }
  export namespace DataSet {
    export interface Attr {
      Arn: string;
      ConsumedSpiceCapacityInBytes: number;
      CreatedTime: string;
      LastUpdatedTime: string;
      OutputColumns: OutputColumn[];
    }
    export interface CalculatedColumn {
      ColumnId: string;
      ColumnName: string;
      Expression: string;
    }
    export interface CastColumnTypeOperation {
      ColumnName: string;
      Format?: string;
      NewColumnType: string;
    }
    export interface ColumnDescription {
      Text?: string;
    }
    export interface ColumnGroup {
      GeoSpatialColumnGroup?: GeoSpatialColumnGroup;
    }
    export interface ColumnLevelPermissionRule {
      ColumnNames?: string[];
      Principals?: string[];
    }
    export interface ColumnTag {
      ColumnDescription?: ColumnDescription;
      ColumnGeographicRole?: string;
    }
    export interface CreateColumnsOperation {
      Columns: CalculatedColumn[];
    }
    export interface CustomSql {
      Columns: InputColumn[];
      DataSourceArn: string;
      Name: string;
      SqlQuery: string;
    }
    export interface DataSetUsageConfiguration {
      DisableUseAsDirectQuerySource?: boolean;
      DisableUseAsImportedSource?: boolean;
    }
    export interface FieldFolder {
      Columns?: string[];
      Description?: string;
    }
    export interface FilterOperation {
      ConditionExpression: string;
    }
    export interface GeoSpatialColumnGroup {
      Columns: string[];
      CountryCode?: string;
      Name: string;
    }
    export interface IngestionWaitPolicy {
      IngestionWaitTimeInHours?: number;
      WaitForSpiceIngestion?: boolean;
    }
    export interface InputColumn {
      Name: string;
      Type: string;
    }
    export interface JoinInstruction {
      LeftJoinKeyProperties?: JoinKeyProperties;
      LeftOperand: string;
      OnClause: string;
      RightJoinKeyProperties?: JoinKeyProperties;
      RightOperand: string;
      Type: string;
    }
    export interface JoinKeyProperties {
      UniqueKey?: boolean;
    }
    export interface LogicalTable {
      Alias: string;
      DataTransforms?: TransformOperation[];
      Source: LogicalTableSource;
    }
    export interface LogicalTableSource {
      DataSetArn?: string;
      JoinInstruction?: JoinInstruction;
      PhysicalTableId?: string;
    }
    export interface OutputColumn {
      Description?: string;
      Name?: string;
      Type?: string;
    }
    export interface PhysicalTable {
      CustomSql?: CustomSql;
      RelationalTable?: RelationalTable;
      S3Source?: S3Source;
    }
    export interface ProjectOperation {
      ProjectedColumns: string[];
    }
    export interface RelationalTable {
      Catalog?: string;
      DataSourceArn: string;
      InputColumns: InputColumn[];
      Name: string;
      Schema?: string;
    }
    export interface RenameColumnOperation {
      ColumnName: string;
      NewColumnName: string;
    }
    export interface ResourcePermission {
      Actions: string[];
      Principal: string;
    }
    export interface RowLevelPermissionDataSet {
      Arn: string;
      FormatVersion?: string;
      Namespace?: string;
      PermissionPolicy: string;
    }
    export interface S3Source {
      DataSourceArn: string;
      InputColumns: InputColumn[];
      UploadSettings?: UploadSettings;
    }
    export interface TagColumnOperation {
      ColumnName: string;
      Tags: ColumnTag[];
    }
    export interface TransformOperation {
      CastColumnTypeOperation?: CastColumnTypeOperation;
      CreateColumnsOperation?: CreateColumnsOperation;
      FilterOperation?: FilterOperation;
      ProjectOperation?: ProjectOperation;
      RenameColumnOperation?: RenameColumnOperation;
      TagColumnOperation?: TagColumnOperation;
    }
    export interface UploadSettings {
      ContainsHeader?: boolean;
      Delimiter?: string;
      Format?: string;
      StartFromRow?: number;
      TextQualifier?: string;
    }
  }
  export interface DataSource {
    AlternateDataSourceParameters?: DataSource.DataSourceParameters[];
    AwsAccountId?: string;
    Credentials?: DataSource.DataSourceCredentials;
    DataSourceId?: string;
    DataSourceParameters?: DataSource.DataSourceParameters;
    ErrorInfo?: DataSource.DataSourceErrorInfo;
    Name?: string;
    Permissions?: DataSource.ResourcePermission[];
    SslProperties?: DataSource.SslProperties;
    Tags?: Tag[];
    Type?: string;
    VpcConnectionProperties?: DataSource.VpcConnectionProperties;
  }
  export namespace DataSource {
    export interface Attr {
      Arn: string;
      CreatedTime: string;
      LastUpdatedTime: string;
      Status: string;
    }
    export interface AmazonElasticsearchParameters {
      Domain: string;
    }
    export interface AmazonOpenSearchParameters {
      Domain: string;
    }
    export interface AthenaParameters {
      WorkGroup?: string;
    }
    export interface AuroraParameters {
      Database: string;
      Host: string;
      Port: number;
    }
    export interface AuroraPostgreSqlParameters {
      Database: string;
      Host: string;
      Port: number;
    }
    export interface CredentialPair {
      AlternateDataSourceParameters?: DataSourceParameters[];
      Password: string;
      Username: string;
    }
    export interface DataSourceCredentials {
      CopySourceArn?: string;
      CredentialPair?: CredentialPair;
      SecretArn?: string;
    }
    export interface DataSourceErrorInfo {
      Message?: string;
      Type?: string;
    }
    export interface DataSourceParameters {
      AmazonElasticsearchParameters?: AmazonElasticsearchParameters;
      AmazonOpenSearchParameters?: AmazonOpenSearchParameters;
      AthenaParameters?: AthenaParameters;
      AuroraParameters?: AuroraParameters;
      AuroraPostgreSqlParameters?: AuroraPostgreSqlParameters;
      DatabricksParameters?: DatabricksParameters;
      MariaDbParameters?: MariaDbParameters;
      MySqlParameters?: MySqlParameters;
      OracleParameters?: OracleParameters;
      PostgreSqlParameters?: PostgreSqlParameters;
      PrestoParameters?: PrestoParameters;
      RdsParameters?: RdsParameters;
      RedshiftParameters?: RedshiftParameters;
      S3Parameters?: S3Parameters;
      SnowflakeParameters?: SnowflakeParameters;
      SparkParameters?: SparkParameters;
      SqlServerParameters?: SqlServerParameters;
      TeradataParameters?: TeradataParameters;
    }
    export interface DatabricksParameters {
      Host: string;
      Port: number;
      SqlEndpointPath: string;
    }
    export interface ManifestFileLocation {
      Bucket: string;
      Key: string;
    }
    export interface MariaDbParameters {
      Database: string;
      Host: string;
      Port: number;
    }
    export interface MySqlParameters {
      Database: string;
      Host: string;
      Port: number;
    }
    export interface OracleParameters {
      Database: string;
      Host: string;
      Port: number;
    }
    export interface PostgreSqlParameters {
      Database: string;
      Host: string;
      Port: number;
    }
    export interface PrestoParameters {
      Catalog: string;
      Host: string;
      Port: number;
    }
    export interface RdsParameters {
      Database: string;
      InstanceId: string;
    }
    export interface RedshiftParameters {
      ClusterId?: string;
      Database: string;
      Host?: string;
      Port?: number;
    }
    export interface ResourcePermission {
      Actions: string[];
      Principal: string;
    }
    export interface S3Parameters {
      ManifestFileLocation: ManifestFileLocation;
    }
    export interface SnowflakeParameters {
      Database: string;
      Host: string;
      Warehouse: string;
    }
    export interface SparkParameters {
      Host: string;
      Port: number;
    }
    export interface SqlServerParameters {
      Database: string;
      Host: string;
      Port: number;
    }
    export interface SslProperties {
      DisableSsl?: boolean;
    }
    export interface TeradataParameters {
      Database: string;
      Host: string;
      Port: number;
    }
    export interface VpcConnectionProperties {
      VpcConnectionArn: string;
    }
  }
  export interface Template {
    AwsAccountId: string;
    Name?: string;
    Permissions?: Template.ResourcePermission[];
    SourceEntity: Template.TemplateSourceEntity;
    Tags?: Tag[];
    TemplateId: string;
    VersionDescription?: string;
  }
  export namespace Template {
    export interface Attr {
      Arn: string;
      CreatedTime: string;
      LastUpdatedTime: string;
      "Version.CreatedTime": string;
      "Version.DataSetConfigurations": DataSetConfiguration[];
      "Version.Description": string;
      "Version.Errors": TemplateError[];
      "Version.Sheets": Sheet[];
      "Version.SourceEntityArn": string;
      "Version.Status": string;
      "Version.ThemeArn": string;
      "Version.VersionNumber": number;
    }
    export interface ColumnGroupColumnSchema {
      Name?: string;
    }
    export interface ColumnGroupSchema {
      ColumnGroupColumnSchemaList?: ColumnGroupColumnSchema[];
      Name?: string;
    }
    export interface ColumnSchema {
      DataType?: string;
      GeographicRole?: string;
      Name?: string;
    }
    export interface DataSetConfiguration {
      ColumnGroupSchemaList?: ColumnGroupSchema[];
      DataSetSchema?: DataSetSchema;
      Placeholder?: string;
    }
    export interface DataSetReference {
      DataSetArn: string;
      DataSetPlaceholder: string;
    }
    export interface DataSetSchema {
      ColumnSchemaList?: ColumnSchema[];
    }
    export interface ResourcePermission {
      Actions: string[];
      Principal: string;
    }
    export interface Sheet {
      Name?: string;
      SheetId?: string;
    }
    export interface TemplateError {
      Message?: string;
      Type?: string;
    }
    export interface TemplateSourceAnalysis {
      Arn: string;
      DataSetReferences: DataSetReference[];
    }
    export interface TemplateSourceEntity {
      SourceAnalysis?: TemplateSourceAnalysis;
      SourceTemplate?: TemplateSourceTemplate;
    }
    export interface TemplateSourceTemplate {
      Arn: string;
    }
    export interface TemplateVersion {
      CreatedTime?: string;
      DataSetConfigurations?: DataSetConfiguration[];
      Description?: string;
      Errors?: TemplateError[];
      Sheets?: Sheet[];
      SourceEntityArn?: string;
      Status?: string;
      ThemeArn?: string;
      VersionNumber?: number;
    }
  }
  export interface Theme {
    AwsAccountId: string;
    BaseThemeId?: string;
    Configuration?: Theme.ThemeConfiguration;
    Name?: string;
    Permissions?: Theme.ResourcePermission[];
    Tags?: Tag[];
    ThemeId: string;
    VersionDescription?: string;
  }
  export namespace Theme {
    export interface Attr {
      Arn: string;
      CreatedTime: string;
      LastUpdatedTime: string;
      Type: string;
      "Version.Arn": string;
      "Version.BaseThemeId": string;
      "Version.CreatedTime": string;
      "Version.Description": string;
      "Version.Errors": ThemeError[];
      "Version.Status": string;
      "Version.VersionNumber": number;
    }
    export interface BorderStyle {
      Show?: boolean;
    }
    export interface DataColorPalette {
      Colors?: string[];
      EmptyFillColor?: string;
      MinMaxGradient?: string[];
    }
    export interface Font {
      FontFamily?: string;
    }
    export interface GutterStyle {
      Show?: boolean;
    }
    export interface MarginStyle {
      Show?: boolean;
    }
    export interface ResourcePermission {
      Actions: string[];
      Principal: string;
    }
    export interface SheetStyle {
      Tile?: TileStyle;
      TileLayout?: TileLayoutStyle;
    }
    export interface ThemeConfiguration {
      DataColorPalette?: DataColorPalette;
      Sheet?: SheetStyle;
      Typography?: Typography;
      UIColorPalette?: UIColorPalette;
    }
    export interface ThemeError {
      Message?: string;
      Type?: string;
    }
    export interface ThemeVersion {
      Arn?: string;
      BaseThemeId?: string;
      Configuration?: ThemeConfiguration;
      CreatedTime?: string;
      Description?: string;
      Errors?: ThemeError[];
      Status?: string;
      VersionNumber?: number;
    }
    export interface TileLayoutStyle {
      Gutter?: GutterStyle;
      Margin?: MarginStyle;
    }
    export interface TileStyle {
      Border?: BorderStyle;
    }
    export interface Typography {
      FontFamilies?: Font[];
    }
    export interface UIColorPalette {
      Accent?: string;
      AccentForeground?: string;
      Danger?: string;
      DangerForeground?: string;
      Dimension?: string;
      DimensionForeground?: string;
      Measure?: string;
      MeasureForeground?: string;
      PrimaryBackground?: string;
      PrimaryForeground?: string;
      SecondaryBackground?: string;
      SecondaryForeground?: string;
      Success?: string;
      SuccessForeground?: string;
      Warning?: string;
      WarningForeground?: string;
    }
  }
}
export namespace RAM {
  export interface ResourceShare {
    AllowExternalPrincipals?: boolean;
    Name: string;
    PermissionArns?: string[];
    Principals?: string[];
    ResourceArns?: string[];
    Tags?: Tag[];
  }
}
export namespace RDS {
  export interface DBCluster {
    AllocatedStorage?: number;
    AssociatedRoles?: DBCluster.DBClusterRole[];
    AutoMinorVersionUpgrade?: boolean;
    AvailabilityZones?: string[];
    BacktrackWindow?: number;
    BackupRetentionPeriod?: number;
    CopyTagsToSnapshot?: boolean;
    DBClusterIdentifier?: string;
    DBClusterInstanceClass?: string;
    DBClusterParameterGroupName?: string;
    DBInstanceParameterGroupName?: string;
    DBSubnetGroupName?: string;
    DBSystemId?: string;
    DatabaseName?: string;
    DeletionProtection?: boolean;
    Domain?: string;
    DomainIAMRoleName?: string;
    EnableCloudwatchLogsExports?: string[];
    EnableHttpEndpoint?: boolean;
    EnableIAMDatabaseAuthentication?: boolean;
    Engine?: string;
    EngineMode?: string;
    EngineVersion?: string;
    GlobalClusterIdentifier?: string;
    Iops?: number;
    KmsKeyId?: string;
    ManageMasterUserPassword?: boolean;
    MasterUserPassword?: string;
    MasterUserSecret?: DBCluster.MasterUserSecret;
    MasterUsername?: string;
    MonitoringInterval?: number;
    MonitoringRoleArn?: string;
    NetworkType?: string;
    PerformanceInsightsEnabled?: boolean;
    PerformanceInsightsKmsKeyId?: string;
    PerformanceInsightsRetentionPeriod?: number;
    Port?: number;
    PreferredBackupWindow?: string;
    PreferredMaintenanceWindow?: string;
    PubliclyAccessible?: boolean;
    ReplicationSourceIdentifier?: string;
    RestoreType?: string;
    ScalingConfiguration?: DBCluster.ScalingConfiguration;
    ServerlessV2ScalingConfiguration?: DBCluster.ServerlessV2ScalingConfiguration;
    SnapshotIdentifier?: string;
    SourceDBClusterIdentifier?: string;
    SourceRegion?: string;
    StorageEncrypted?: boolean;
    StorageType?: string;
    Tags?: Tag[];
    UseLatestRestorableTime?: boolean;
    VpcSecurityGroupIds?: string[];
  }
  export namespace DBCluster {
    export interface Attr {
      DBClusterArn: string;
      DBClusterResourceId: string;
      "Endpoint.Address": string;
      "Endpoint.Port": string;
      "MasterUserSecret.SecretArn": string;
      "ReadEndpoint.Address": string;
    }
    export interface DBClusterRole {
      FeatureName?: string;
      RoleArn: string;
    }
    export interface Endpoint {
      Address?: string;
      Port?: string;
    }
    export interface MasterUserSecret {
      KmsKeyId?: string;
      SecretArn?: string;
    }
    export interface ReadEndpoint {
      Address?: string;
    }
    export interface ScalingConfiguration {
      AutoPause?: boolean;
      MaxCapacity?: number;
      MinCapacity?: number;
      SecondsBeforeTimeout?: number;
      SecondsUntilAutoPause?: number;
      TimeoutAction?: string;
    }
    export interface ServerlessV2ScalingConfiguration {
      MaxCapacity?: number;
      MinCapacity?: number;
    }
  }
  export interface DBClusterParameterGroup {
    DBClusterParameterGroupName?: string;
    Description: string;
    Family: string;
    Parameters: any;
    Tags?: Tag[];
  }
  export interface DBInstance {
    AllocatedStorage?: string;
    AllowMajorVersionUpgrade?: boolean;
    AssociatedRoles?: DBInstance.DBInstanceRole[];
    AutoMinorVersionUpgrade?: boolean;
    AvailabilityZone?: string;
    BackupRetentionPeriod?: number;
    CACertificateIdentifier?: string;
    CertificateDetails?: DBInstance.CertificateDetails;
    CertificateRotationRestart?: boolean;
    CharacterSetName?: string;
    CopyTagsToSnapshot?: boolean;
    CustomIAMInstanceProfile?: string;
    DBClusterIdentifier?: string;
    DBClusterSnapshotIdentifier?: string;
    DBInstanceClass?: string;
    DBInstanceIdentifier?: string;
    DBName?: string;
    DBParameterGroupName?: string;
    DBSecurityGroups?: string[];
    DBSnapshotIdentifier?: string;
    DBSubnetGroupName?: string;
    DeleteAutomatedBackups?: boolean;
    DeletionProtection?: boolean;
    Domain?: string;
    DomainIAMRoleName?: string;
    EnableCloudwatchLogsExports?: string[];
    EnableIAMDatabaseAuthentication?: boolean;
    EnablePerformanceInsights?: boolean;
    Endpoint?: DBInstance.Endpoint;
    Engine?: string;
    EngineVersion?: string;
    Iops?: number;
    KmsKeyId?: string;
    LicenseModel?: string;
    ManageMasterUserPassword?: boolean;
    MasterUserPassword?: string;
    MasterUserSecret?: DBInstance.MasterUserSecret;
    MasterUsername?: string;
    MaxAllocatedStorage?: number;
    MonitoringInterval?: number;
    MonitoringRoleArn?: string;
    MultiAZ?: boolean;
    NcharCharacterSetName?: string;
    NetworkType?: string;
    OptionGroupName?: string;
    PerformanceInsightsKMSKeyId?: string;
    PerformanceInsightsRetentionPeriod?: number;
    Port?: string;
    PreferredBackupWindow?: string;
    PreferredMaintenanceWindow?: string;
    ProcessorFeatures?: DBInstance.ProcessorFeature[];
    PromotionTier?: number;
    PubliclyAccessible?: boolean;
    ReplicaMode?: string;
    RestoreTime?: string;
    SourceDBInstanceAutomatedBackupsArn?: string;
    SourceDBInstanceIdentifier?: string;
    SourceDbiResourceId?: string;
    SourceRegion?: string;
    StorageEncrypted?: boolean;
    StorageThroughput?: number;
    StorageType?: string;
    Tags?: Tag[];
    Timezone?: string;
    UseDefaultProcessorFeatures?: boolean;
    UseLatestRestorableTime?: boolean;
    VPCSecurityGroups?: string[];
  }
  export namespace DBInstance {
    export interface Attr {
      "CertificateDetails.CAIdentifier": string;
      "CertificateDetails.ValidTill": string;
      DBInstanceArn: string;
      DBSystemId: string;
      DbiResourceId: string;
      "Endpoint.Address": string;
      "Endpoint.HostedZoneId": string;
      "Endpoint.Port": string;
      "MasterUserSecret.SecretArn": string;
    }
    export interface CertificateDetails {
      CAIdentifier?: string;
      ValidTill?: string;
    }
    export interface DBInstanceRole {
      FeatureName: string;
      RoleArn: string;
    }
    export interface Endpoint {
      Address?: string;
      HostedZoneId?: string;
      Port?: string;
    }
    export interface MasterUserSecret {
      KmsKeyId?: string;
      SecretArn?: string;
    }
    export interface ProcessorFeature {
      Name?: string;
      Value?: string;
    }
  }
  export interface DBParameterGroup {
    DBParameterGroupName?: string;
    Description: string;
    Family: string;
    Parameters?: any;
    Tags?: Tag[];
  }
  export interface DBProxy {
    Auth: DBProxy.AuthFormat[];
    DBProxyName: string;
    DebugLogging?: boolean;
    EngineFamily: string;
    IdleClientTimeout?: number;
    RequireTLS?: boolean;
    RoleArn: string;
    Tags?: DBProxy.TagFormat[];
    VpcSecurityGroupIds?: string[];
    VpcSubnetIds: string[];
  }
  export namespace DBProxy {
    export interface Attr {
      DBProxyArn: string;
      Endpoint: string;
      VpcId: string;
    }
    export interface AuthFormat {
      AuthScheme?: string;
      ClientPasswordAuthType?: string;
      Description?: string;
      IAMAuth?: string;
      SecretArn?: string;
      UserName?: string;
    }
    export interface TagFormat {
      Key?: string;
      Value?: string;
    }
  }
  export interface DBProxyEndpoint {
    DBProxyEndpointName: string;
    DBProxyName: string;
    Tags?: DBProxyEndpoint.TagFormat[];
    TargetRole?: string;
    VpcSecurityGroupIds?: string[];
    VpcSubnetIds: string[];
  }
  export namespace DBProxyEndpoint {
    export interface Attr {
      DBProxyEndpointArn: string;
      Endpoint: string;
      IsDefault: boolean;
      VpcId: string;
    }
    export interface TagFormat {
      Key?: string;
      Value?: string;
    }
  }
  export interface DBProxyTargetGroup {
    ConnectionPoolConfigurationInfo?: DBProxyTargetGroup.ConnectionPoolConfigurationInfoFormat;
    DBClusterIdentifiers?: string[];
    DBInstanceIdentifiers?: string[];
    DBProxyName: string;
    TargetGroupName: string;
  }
  export namespace DBProxyTargetGroup {
    export interface Attr {
      TargetGroupArn: string;
    }
    export interface ConnectionPoolConfigurationInfoFormat {
      ConnectionBorrowTimeout?: number;
      InitQuery?: string;
      MaxConnectionsPercent?: number;
      MaxIdleConnectionsPercent?: number;
      SessionPinningFilters?: string[];
    }
  }
  export interface DBSecurityGroup {
    DBSecurityGroupIngress: DBSecurityGroup.Ingress[];
    EC2VpcId?: string;
    GroupDescription: string;
    Tags?: Tag[];
  }
  export namespace DBSecurityGroup {
    export interface Attr {}
    export interface Ingress {
      CIDRIP?: string;
      EC2SecurityGroupId?: string;
      EC2SecurityGroupName?: string;
      EC2SecurityGroupOwnerId?: string;
    }
  }
  export interface DBSecurityGroupIngress {
    CIDRIP?: string;
    DBSecurityGroupName: string;
    EC2SecurityGroupId?: string;
    EC2SecurityGroupName?: string;
    EC2SecurityGroupOwnerId?: string;
  }
  export interface DBSubnetGroup {
    DBSubnetGroupDescription: string;
    DBSubnetGroupName?: string;
    SubnetIds: string[];
    Tags?: Tag[];
  }
  export interface EventSubscription {
    Enabled?: boolean;
    EventCategories?: string[];
    SnsTopicArn: string;
    SourceIds?: string[];
    SourceType?: string;
    SubscriptionName?: string;
    Tags?: Tag[];
  }
  export interface GlobalCluster {
    DeletionProtection?: boolean;
    Engine?: string;
    EngineVersion?: string;
    GlobalClusterIdentifier?: string;
    SourceDBClusterIdentifier?: string;
    StorageEncrypted?: boolean;
  }
  export interface OptionGroup {
    EngineName: string;
    MajorEngineVersion: string;
    OptionConfigurations?: OptionGroup.OptionConfiguration[];
    OptionGroupDescription: string;
    OptionGroupName?: string;
    Tags?: Tag[];
  }
  export namespace OptionGroup {
    export interface Attr {}
    export interface OptionConfiguration {
      DBSecurityGroupMemberships?: string[];
      OptionName: string;
      OptionSettings?: OptionSetting[];
      OptionVersion?: string;
      Port?: number;
      VpcSecurityGroupMemberships?: string[];
    }
    export interface OptionSetting {
      Name?: string;
      Value?: string;
    }
  }
}
export namespace RUM {
  export interface AppMonitor {
    AppMonitorConfiguration?: AppMonitor.AppMonitorConfiguration;
    CwLogEnabled?: boolean;
    Domain: string;
    Name: string;
    Tags?: Tag[];
  }
  export namespace AppMonitor {
    export interface Attr {}
    export interface AppMonitorConfiguration {
      AllowCookies?: boolean;
      EnableXRay?: boolean;
      ExcludedPages?: string[];
      FavoritePages?: string[];
      GuestRoleArn?: string;
      IdentityPoolId?: string;
      IncludedPages?: string[];
      MetricDestinations?: MetricDestination[];
      SessionSampleRate?: number;
      Telemetries?: string[];
    }
    export interface MetricDefinition {
      DimensionKeys?: Record<string, string>;
      EventPattern?: string;
      Name: string;
      UnitLabel?: string;
      ValueKey?: string;
    }
    export interface MetricDestination {
      Destination: string;
      DestinationArn?: string;
      IamRoleArn?: string;
      MetricDefinitions?: MetricDefinition[];
    }
  }
}
export namespace Redshift {
  export interface Cluster {
    AllowVersionUpgrade?: boolean;
    AquaConfigurationStatus?: string;
    AutomatedSnapshotRetentionPeriod?: number;
    AvailabilityZone?: string;
    AvailabilityZoneRelocation?: boolean;
    AvailabilityZoneRelocationStatus?: string;
    Classic?: boolean;
    ClusterIdentifier?: string;
    ClusterParameterGroupName?: string;
    ClusterSecurityGroups?: string[];
    ClusterSubnetGroupName?: string;
    ClusterType: string;
    ClusterVersion?: string;
    DBName: string;
    DeferMaintenance?: boolean;
    DeferMaintenanceDuration?: number;
    DeferMaintenanceEndTime?: string;
    DeferMaintenanceStartTime?: string;
    DestinationRegion?: string;
    ElasticIp?: string;
    Encrypted?: boolean;
    Endpoint?: Cluster.Endpoint;
    EnhancedVpcRouting?: boolean;
    HsmClientCertificateIdentifier?: string;
    HsmConfigurationIdentifier?: string;
    IamRoles?: string[];
    KmsKeyId?: string;
    LoggingProperties?: Cluster.LoggingProperties;
    MaintenanceTrackName?: string;
    ManualSnapshotRetentionPeriod?: number;
    MasterUserPassword: string;
    MasterUsername: string;
    NodeType: string;
    NumberOfNodes?: number;
    OwnerAccount?: string;
    Port?: number;
    PreferredMaintenanceWindow?: string;
    PubliclyAccessible?: boolean;
    ResourceAction?: string;
    RevisionTarget?: string;
    RotateEncryptionKey?: boolean;
    SnapshotClusterIdentifier?: string;
    SnapshotCopyGrantName?: string;
    SnapshotCopyManual?: boolean;
    SnapshotCopyRetentionPeriod?: number;
    SnapshotIdentifier?: string;
    Tags?: Tag[];
    VpcSecurityGroupIds?: string[];
  }
  export namespace Cluster {
    export interface Attr {
      DeferMaintenanceIdentifier: string;
      "Endpoint.Address": string;
      "Endpoint.Port": string;
      Id: string;
    }
    export interface Endpoint {
      Address?: string;
      Port?: string;
    }
    export interface LoggingProperties {
      BucketName: string;
      S3KeyPrefix?: string;
    }
  }
  export interface ClusterParameterGroup {
    Description: string;
    ParameterGroupFamily: string;
    Parameters?: ClusterParameterGroup.Parameter[];
    Tags?: Tag[];
  }
  export namespace ClusterParameterGroup {
    export interface Attr {
      ParameterGroupName: string;
    }
    export interface Parameter {
      ParameterName: string;
      ParameterValue: string;
    }
  }
  export interface ClusterSecurityGroup {
    Description: string;
    Tags?: Tag[];
  }
  export interface ClusterSecurityGroupIngress {
    CIDRIP?: string;
    ClusterSecurityGroupName: string;
    EC2SecurityGroupName?: string;
    EC2SecurityGroupOwnerId?: string;
  }
  export interface ClusterSubnetGroup {
    Description: string;
    SubnetIds: string[];
    Tags?: Tag[];
  }
  export interface EndpointAccess {
    ClusterIdentifier: string;
    EndpointName: string;
    ResourceOwner?: string;
    SubnetGroupName: string;
    VpcEndpoint?: any;
    VpcSecurityGroupIds: string[];
    VpcSecurityGroups?: EndpointAccess.VpcSecurityGroup[];
  }
  export namespace EndpointAccess {
    export interface Attr {
      Address: string;
      EndpointCreateTime: string;
      EndpointStatus: string;
      Port: number;
      "VpcEndpoint.VpcEndpointId": string;
      "VpcEndpoint.VpcId": string;
    }
    export interface NetworkInterface {
      AvailabilityZone?: string;
      NetworkInterfaceId?: string;
      PrivateIpAddress?: string;
      SubnetId?: string;
    }
    export interface VpcEndpoint {
      NetworkInterfaces?: NetworkInterface[];
      VpcEndpointId?: string;
      VpcId?: string;
    }
    export interface VpcSecurityGroup {
      Status?: string;
      VpcSecurityGroupId?: string;
    }
  }
  export interface EndpointAuthorization {
    Account: string;
    ClusterIdentifier: string;
    Force?: boolean;
    VpcIds?: string[];
  }
  export interface EventSubscription {
    Enabled?: boolean;
    EventCategories?: string[];
    Severity?: string;
    SnsTopicArn?: string;
    SourceIds?: string[];
    SourceType?: string;
    SubscriptionName: string;
    Tags?: Tag[];
  }
  export interface ScheduledAction {
    Enable?: boolean;
    EndTime?: string;
    IamRole?: string;
    Schedule?: string;
    ScheduledActionDescription?: string;
    ScheduledActionName: string;
    StartTime?: string;
    TargetAction?: ScheduledAction.ScheduledActionType;
  }
  export namespace ScheduledAction {
    export interface Attr {
      NextInvocations: string[];
      State: string;
    }
    export interface PauseClusterMessage {
      ClusterIdentifier: string;
    }
    export interface ResizeClusterMessage {
      Classic?: boolean;
      ClusterIdentifier: string;
      ClusterType?: string;
      NodeType?: string;
      NumberOfNodes?: number;
    }
    export interface ResumeClusterMessage {
      ClusterIdentifier: string;
    }
    export interface ScheduledActionType {
      PauseCluster?: PauseClusterMessage;
      ResizeCluster?: ResizeClusterMessage;
      ResumeCluster?: ResumeClusterMessage;
    }
  }
}
export namespace RedshiftServerless {
  export interface Namespace {
    AdminUserPassword?: string;
    AdminUsername?: string;
    DbName?: string;
    DefaultIamRoleArn?: string;
    FinalSnapshotName?: string;
    FinalSnapshotRetentionPeriod?: number;
    IamRoles?: string[];
    KmsKeyId?: string;
    LogExports?: string[];
    Namespace?: Namespace.Namespace;
    NamespaceName: string;
    Tags?: Tag[];
  }
  export namespace Namespace {
    export interface Attr {
      "Namespace.AdminUsername": string;
      "Namespace.CreationDate": string;
      "Namespace.DbName": string;
      "Namespace.DefaultIamRoleArn": string;
      "Namespace.IamRoles": string[];
      "Namespace.KmsKeyId": string;
      "Namespace.LogExports": string[];
      "Namespace.NamespaceArn": string;
      "Namespace.NamespaceId": string;
      "Namespace.NamespaceName": string;
      "Namespace.Status": string;
    }
    export interface Namespace {
      AdminUsername?: string;
      CreationDate?: string;
      DbName?: string;
      DefaultIamRoleArn?: string;
      IamRoles?: string[];
      KmsKeyId?: string;
      LogExports?: string[];
      NamespaceArn?: string;
      NamespaceId?: string;
      NamespaceName?: string;
      Status?: string;
    }
  }
  export interface Workgroup {
    BaseCapacity?: number;
    ConfigParameters?: Workgroup.ConfigParameter[];
    EnhancedVpcRouting?: boolean;
    NamespaceName?: string;
    PubliclyAccessible?: boolean;
    SecurityGroupIds?: string[];
    SubnetIds?: string[];
    Tags?: Tag[];
    Workgroup?: Workgroup.Workgroup;
    WorkgroupName: string;
  }
  export namespace Workgroup {
    export interface Attr {
      "Workgroup.BaseCapacity": number;
      "Workgroup.CreationDate": string;
      "Workgroup.Endpoint.Address": string;
      "Workgroup.Endpoint.Port": number;
      "Workgroup.EnhancedVpcRouting": boolean;
      "Workgroup.NamespaceName": string;
      "Workgroup.PubliclyAccessible": boolean;
      "Workgroup.SecurityGroupIds": string[];
      "Workgroup.Status": string;
      "Workgroup.SubnetIds": string[];
      "Workgroup.WorkgroupArn": string;
      "Workgroup.WorkgroupId": string;
      "Workgroup.WorkgroupName": string;
    }
    export interface ConfigParameter {
      ParameterKey?: string;
      ParameterValue?: string;
    }
    export interface Endpoint {
      Address?: string;
      Port?: number;
      VpcEndpoints?: VpcEndpoint[];
    }
    export interface NetworkInterface {
      AvailabilityZone?: string;
      NetworkInterfaceId?: string;
      PrivateIpAddress?: string;
      SubnetId?: string;
    }
    export interface VpcEndpoint {
      NetworkInterfaces?: NetworkInterface[];
      VpcEndpointId?: string;
      VpcId?: string;
    }
    export interface Workgroup {
      BaseCapacity?: number;
      ConfigParameters?: ConfigParameter[];
      CreationDate?: string;
      Endpoint?: Endpoint;
      EnhancedVpcRouting?: boolean;
      NamespaceName?: string;
      PubliclyAccessible?: boolean;
      SecurityGroupIds?: string[];
      Status?: string;
      SubnetIds?: string[];
      WorkgroupArn?: string;
      WorkgroupId?: string;
      WorkgroupName?: string;
    }
  }
}
export namespace RefactorSpaces {
  export interface Application {
    ApiGatewayProxy?: Application.ApiGatewayProxyInput;
    EnvironmentIdentifier?: string;
    Name?: string;
    ProxyType?: string;
    Tags?: Tag[];
    VpcId?: string;
  }
  export namespace Application {
    export interface Attr {
      ApiGatewayId: string;
      ApplicationIdentifier: string;
      Arn: string;
      NlbArn: string;
      NlbName: string;
      ProxyUrl: string;
      StageName: string;
      VpcLinkId: string;
    }
    export interface ApiGatewayProxyInput {
      EndpointType?: string;
      StageName?: string;
    }
  }
  export interface Environment {
    Description?: string;
    Name?: string;
    NetworkFabricType?: string;
    Tags?: Tag[];
  }
  export interface Route {
    ApplicationIdentifier: string;
    DefaultRoute?: Route.DefaultRouteInput;
    EnvironmentIdentifier: string;
    RouteType?: string;
    ServiceIdentifier: string;
    Tags?: Tag[];
    UriPathRoute?: Route.UriPathRouteInput;
  }
  export namespace Route {
    export interface Attr {
      Arn: string;
      PathResourceToId: string;
      RouteIdentifier: string;
    }
    export interface DefaultRouteInput {
      ActivationState: string;
    }
    export interface UriPathRouteInput {
      ActivationState: string;
      IncludeChildPaths?: boolean;
      Methods?: string[];
      SourcePath?: string;
    }
  }
  export interface Service {
    ApplicationIdentifier: string;
    Description?: string;
    EndpointType?: string;
    EnvironmentIdentifier: string;
    LambdaEndpoint?: Service.LambdaEndpointInput;
    Name?: string;
    Tags?: Tag[];
    UrlEndpoint?: Service.UrlEndpointInput;
    VpcId?: string;
  }
  export namespace Service {
    export interface Attr {
      Arn: string;
      ServiceIdentifier: string;
    }
    export interface LambdaEndpointInput {
      Arn: string;
    }
    export interface UrlEndpointInput {
      HealthUrl?: string;
      Url: string;
    }
  }
}
export namespace Rekognition {
  export interface Collection {
    CollectionId: string;
    Tags?: Tag[];
  }
  export interface Project {
    ProjectName: string;
  }
  export interface StreamProcessor {
    BoundingBoxRegionsOfInterest?: StreamProcessor.BoundingBox[];
    ConnectedHomeSettings?: StreamProcessor.ConnectedHomeSettings;
    DataSharingPreference?: StreamProcessor.DataSharingPreference;
    FaceSearchSettings?: StreamProcessor.FaceSearchSettings;
    KinesisDataStream?: StreamProcessor.KinesisDataStream;
    KinesisVideoStream: StreamProcessor.KinesisVideoStream;
    KmsKeyId?: string;
    Name?: string;
    NotificationChannel?: StreamProcessor.NotificationChannel;
    PolygonRegionsOfInterest?: any;
    RoleArn: string;
    S3Destination?: StreamProcessor.S3Destination;
    Tags?: Tag[];
  }
  export namespace StreamProcessor {
    export interface Attr {
      Arn: string;
      Status: string;
      StatusMessage: string;
    }
    export interface BoundingBox {
      Height: number;
      Left: number;
      Top: number;
      Width: number;
    }
    export interface ConnectedHomeSettings {
      Labels: string[];
      MinConfidence?: number;
    }
    export interface DataSharingPreference {
      OptIn: boolean;
    }
    export interface FaceSearchSettings {
      CollectionId: string;
      FaceMatchThreshold?: number;
    }
    export interface KinesisDataStream {
      Arn: string;
    }
    export interface KinesisVideoStream {
      Arn: string;
    }
    export interface NotificationChannel {
      Arn: string;
    }
    export interface S3Destination {
      BucketName: string;
      ObjectKeyPrefix?: string;
    }
  }
}
export namespace ResilienceHub {
  export interface App {
    AppAssessmentSchedule?: string;
    AppTemplateBody: string;
    Description?: string;
    Name: string;
    ResiliencyPolicyArn?: string;
    ResourceMappings: App.ResourceMapping[];
    Tags?: Record<string, string>;
  }
  export namespace App {
    export interface Attr {
      AppArn: string;
    }
    export interface PhysicalResourceId {
      AwsAccountId?: string;
      AwsRegion?: string;
      Identifier: string;
      Type: string;
    }
    export interface ResourceMapping {
      LogicalStackName?: string;
      MappingType: string;
      PhysicalResourceId: PhysicalResourceId;
      ResourceName?: string;
      TerraformSourceName?: string;
    }
  }
  export interface ResiliencyPolicy {
    DataLocationConstraint?: string;
    Policy: Record<string, ResiliencyPolicy.FailurePolicy>;
    PolicyDescription?: string;
    PolicyName: string;
    Tags?: Record<string, string>;
    Tier: string;
  }
  export namespace ResiliencyPolicy {
    export interface Attr {
      PolicyArn: string;
    }
    export interface FailurePolicy {
      RpoInSecs: number;
      RtoInSecs: number;
    }
  }
}
export namespace ResourceExplorer2 {
  export interface DefaultViewAssociation {
    ViewArn: string;
  }
  export interface Index {
    Tags?: Record<string, string>;
    Type: string;
  }
  export interface View {
    Filters?: View.Filters;
    IncludedProperties?: View.IncludedProperty[];
    Tags?: Record<string, string>;
    ViewName: string;
  }
  export namespace View {
    export interface Attr {
      ViewArn: string;
    }
    export interface Filters {
      FilterString: string;
    }
    export interface IncludedProperty {
      Name: string;
    }
  }
}
export namespace ResourceGroups {
  export interface Group {
    Configuration?: Group.ConfigurationItem[];
    Description?: string;
    Name: string;
    ResourceQuery?: Group.ResourceQuery;
    Resources?: string[];
    Tags?: Tag[];
  }
  export namespace Group {
    export interface Attr {
      Arn: string;
    }
    export interface ConfigurationItem {
      Parameters?: ConfigurationParameter[];
      Type?: string;
    }
    export interface ConfigurationParameter {
      Name?: string;
      Values?: string[];
    }
    export interface Query {
      ResourceTypeFilters?: string[];
      StackIdentifier?: string;
      TagFilters?: TagFilter[];
    }
    export interface ResourceQuery {
      Query?: Query;
      Type?: string;
    }
    export interface TagFilter {
      Key?: string;
      Values?: string[];
    }
  }
}
export namespace RoboMaker {
  export interface Fleet {
    Name?: string;
    Tags?: Record<string, string>;
  }
  export interface Robot {
    Architecture: string;
    Fleet?: string;
    GreengrassGroupId: string;
    Name?: string;
    Tags?: Record<string, string>;
  }
  export interface RobotApplication {
    CurrentRevisionId?: string;
    Environment?: string;
    Name?: string;
    RobotSoftwareSuite: RobotApplication.RobotSoftwareSuite;
    Sources?: RobotApplication.SourceConfig[];
    Tags?: Record<string, string>;
  }
  export namespace RobotApplication {
    export interface Attr {
      Arn: string;
      CurrentRevisionId: string;
    }
    export interface RobotSoftwareSuite {
      Name: string;
      Version?: string;
    }
    export interface SourceConfig {
      Architecture: string;
      S3Bucket: string;
      S3Key: string;
    }
  }
  export interface RobotApplicationVersion {
    Application: string;
    CurrentRevisionId?: string;
  }
  export interface SimulationApplication {
    CurrentRevisionId?: string;
    Environment?: string;
    Name?: string;
    RenderingEngine?: SimulationApplication.RenderingEngine;
    RobotSoftwareSuite: SimulationApplication.RobotSoftwareSuite;
    SimulationSoftwareSuite: SimulationApplication.SimulationSoftwareSuite;
    Sources?: SimulationApplication.SourceConfig[];
    Tags?: Record<string, string>;
  }
  export namespace SimulationApplication {
    export interface Attr {
      Arn: string;
      CurrentRevisionId: string;
    }
    export interface RenderingEngine {
      Name: string;
      Version: string;
    }
    export interface RobotSoftwareSuite {
      Name: string;
      Version?: string;
    }
    export interface SimulationSoftwareSuite {
      Name: string;
      Version?: string;
    }
    export interface SourceConfig {
      Architecture: string;
      S3Bucket: string;
      S3Key: string;
    }
  }
  export interface SimulationApplicationVersion {
    Application: string;
    CurrentRevisionId?: string;
  }
}
export namespace RolesAnywhere {
  export interface CRL {
    CrlData?: string;
    Enabled?: boolean;
    Name?: string;
    Tags?: Tag[];
    TrustAnchorArn?: string;
  }
  export interface Profile {
    DurationSeconds?: number;
    Enabled?: boolean;
    ManagedPolicyArns?: string[];
    Name?: string;
    RequireInstanceProperties?: boolean;
    RoleArns?: string[];
    SessionPolicy?: string;
    Tags?: Tag[];
  }
  export interface TrustAnchor {
    Enabled?: boolean;
    Name?: string;
    Source?: TrustAnchor.Source;
    Tags?: Tag[];
  }
  export namespace TrustAnchor {
    export interface Attr {
      TrustAnchorArn: string;
      TrustAnchorId: string;
    }
    export interface Source {
      SourceData?: SourceData;
      SourceType?: string;
    }
    export interface SourceData {
      AcmPcaArn?: string;
      X509CertificateData?: string;
    }
  }
}
export namespace Route53 {
  export interface CidrCollection {
    Locations?: CidrCollection.Location[];
    Name: string;
  }
  export namespace CidrCollection {
    export interface Attr {
      Arn: string;
      Id: string;
    }
    export interface Location {
      CidrList: string[];
      LocationName: string;
    }
  }
  export interface DNSSEC {
    HostedZoneId: string;
  }
  export interface HealthCheck {
    HealthCheckConfig: HealthCheck.HealthCheckConfig;
    HealthCheckTags?: HealthCheck.HealthCheckTag[];
  }
  export namespace HealthCheck {
    export interface Attr {
      HealthCheckId: string;
    }
    export interface AlarmIdentifier {
      Name: string;
      Region: string;
    }
    export interface HealthCheckConfig {
      AlarmIdentifier?: AlarmIdentifier;
      ChildHealthChecks?: string[];
      EnableSNI?: boolean;
      FailureThreshold?: number;
      FullyQualifiedDomainName?: string;
      HealthThreshold?: number;
      IPAddress?: string;
      InsufficientDataHealthStatus?: string;
      Inverted?: boolean;
      MeasureLatency?: boolean;
      Port?: number;
      Regions?: string[];
      RequestInterval?: number;
      ResourcePath?: string;
      RoutingControlArn?: string;
      SearchString?: string;
      Type: string;
    }
    export interface HealthCheckTag {
      Key: string;
      Value: string;
    }
  }
  export interface HostedZone {
    HostedZoneConfig?: HostedZone.HostedZoneConfig;
    HostedZoneTags?: HostedZone.HostedZoneTag[];
    Name?: string;
    QueryLoggingConfig?: HostedZone.QueryLoggingConfig;
    VPCs?: HostedZone.VPC[];
  }
  export namespace HostedZone {
    export interface Attr {
      Id: string;
      NameServers: string[];
    }
    export interface HostedZoneConfig {
      Comment?: string;
    }
    export interface HostedZoneTag {
      Key: string;
      Value: string;
    }
    export interface QueryLoggingConfig {
      CloudWatchLogsLogGroupArn: string;
    }
    export interface VPC {
      VPCId: string;
      VPCRegion: string;
    }
  }
  export interface KeySigningKey {
    HostedZoneId: string;
    KeyManagementServiceArn: string;
    Name: string;
    Status: string;
  }
  export interface RecordSet {
    AliasTarget?: RecordSet.AliasTarget;
    CidrRoutingConfig?: RecordSet.CidrRoutingConfig;
    Comment?: string;
    Failover?: string;
    GeoLocation?: RecordSet.GeoLocation;
    HealthCheckId?: string;
    HostedZoneId?: string;
    HostedZoneName?: string;
    MultiValueAnswer?: boolean;
    Name: string;
    Region?: string;
    ResourceRecords?: string[];
    SetIdentifier?: string;
    TTL?: string;
    Type: string;
    Weight?: number;
  }
  export namespace RecordSet {
    export interface Attr {}
    export interface AliasTarget {
      DNSName: string;
      EvaluateTargetHealth?: boolean;
      HostedZoneId: string;
    }
    export interface CidrRoutingConfig {
      CollectionId: string;
      LocationName: string;
    }
    export interface GeoLocation {
      ContinentCode?: string;
      CountryCode?: string;
      SubdivisionCode?: string;
    }
  }
  export interface RecordSetGroup {
    Comment?: string;
    HostedZoneId?: string;
    HostedZoneName?: string;
    RecordSets?: RecordSetGroup.RecordSet[];
  }
  export namespace RecordSetGroup {
    export interface Attr {}
    export interface AliasTarget {
      DNSName: string;
      EvaluateTargetHealth?: boolean;
      HostedZoneId: string;
    }
    export interface CidrRoutingConfig {
      CollectionId: string;
      LocationName: string;
    }
    export interface GeoLocation {
      ContinentCode?: string;
      CountryCode?: string;
      SubdivisionCode?: string;
    }
    export interface RecordSet {
      AliasTarget?: AliasTarget;
      CidrRoutingConfig?: CidrRoutingConfig;
      Failover?: string;
      GeoLocation?: GeoLocation;
      HealthCheckId?: string;
      HostedZoneId?: string;
      HostedZoneName?: string;
      MultiValueAnswer?: boolean;
      Name: string;
      Region?: string;
      ResourceRecords?: string[];
      SetIdentifier?: string;
      TTL?: string;
      Type: string;
      Weight?: number;
    }
  }
}
export namespace Route53RecoveryControl {
  export interface Cluster {
    ClusterEndpoints?: Cluster.ClusterEndpoint[];
    Name?: string;
    Tags?: Tag[];
  }
  export namespace Cluster {
    export interface Attr {
      ClusterArn: string;
      Status: string;
    }
    export interface ClusterEndpoint {
      Endpoint?: string;
      Region?: string;
    }
  }
  export interface ControlPanel {
    ClusterArn?: string;
    Name: string;
    Tags?: Tag[];
  }
  export interface RoutingControl {
    ClusterArn?: string;
    ControlPanelArn?: string;
    Name: string;
  }
  export interface SafetyRule {
    AssertionRule?: SafetyRule.AssertionRule;
    ControlPanelArn: string;
    GatingRule?: SafetyRule.GatingRule;
    Name: string;
    RuleConfig: SafetyRule.RuleConfig;
    Tags?: Tag[];
  }
  export namespace SafetyRule {
    export interface Attr {
      SafetyRuleArn: string;
      Status: string;
    }
    export interface AssertionRule {
      AssertedControls: string[];
      WaitPeriodMs: number;
    }
    export interface GatingRule {
      GatingControls: string[];
      TargetControls: string[];
      WaitPeriodMs: number;
    }
    export interface RuleConfig {
      Inverted: boolean;
      Threshold: number;
      Type: string;
    }
  }
}
export namespace Route53RecoveryReadiness {
  export interface Cell {
    CellName?: string;
    Cells?: string[];
    Tags?: Tag[];
  }
  export interface ReadinessCheck {
    ReadinessCheckName?: string;
    ResourceSetName?: string;
    Tags?: Tag[];
  }
  export interface RecoveryGroup {
    Cells?: string[];
    RecoveryGroupName?: string;
    Tags?: Tag[];
  }
  export interface ResourceSet {
    ResourceSetName?: string;
    ResourceSetType: string;
    Resources: ResourceSet.Resource[];
    Tags?: Tag[];
  }
  export namespace ResourceSet {
    export interface Attr {
      ResourceSetArn: string;
    }
    export interface DNSTargetResource {
      DomainName?: string;
      HostedZoneArn?: string;
      RecordSetId?: string;
      RecordType?: string;
      TargetResource?: TargetResource;
    }
    export interface NLBResource {
      Arn?: string;
    }
    export interface R53ResourceRecord {
      DomainName?: string;
      RecordSetId?: string;
    }
    export interface Resource {
      ComponentId?: string;
      DnsTargetResource?: DNSTargetResource;
      ReadinessScopes?: string[];
      ResourceArn?: string;
    }
    export interface TargetResource {
      NLBResource?: NLBResource;
      R53Resource?: R53ResourceRecord;
    }
  }
}
export namespace Route53Resolver {
  export interface FirewallDomainList {
    DomainFileUrl?: string;
    Domains?: string[];
    Name?: string;
    Tags?: Tag[];
  }
  export interface FirewallRuleGroup {
    FirewallRules?: FirewallRuleGroup.FirewallRule[];
    Name?: string;
    Tags?: Tag[];
  }
  export namespace FirewallRuleGroup {
    export interface Attr {
      Arn: string;
      CreationTime: string;
      CreatorRequestId: string;
      Id: string;
      ModificationTime: string;
      OwnerId: string;
      RuleCount: number;
      ShareStatus: string;
      Status: string;
      StatusMessage: string;
    }
    export interface FirewallRule {
      Action: string;
      BlockOverrideDnsType?: string;
      BlockOverrideDomain?: string;
      BlockOverrideTtl?: number;
      BlockResponse?: string;
      FirewallDomainListId: string;
      Priority: number;
    }
  }
  export interface FirewallRuleGroupAssociation {
    FirewallRuleGroupId: string;
    MutationProtection?: string;
    Name?: string;
    Priority: number;
    Tags?: Tag[];
    VpcId: string;
  }
  export interface ResolverConfig {
    AutodefinedReverseFlag: string;
    ResourceId: string;
  }
  export interface ResolverDNSSECConfig {
    ResourceId?: string;
  }
  export interface ResolverEndpoint {
    Direction: string;
    IpAddresses: ResolverEndpoint.IpAddressRequest[];
    Name?: string;
    OutpostArn?: string;
    PreferredInstanceType?: string;
    SecurityGroupIds: string[];
    Tags?: Tag[];
  }
  export namespace ResolverEndpoint {
    export interface Attr {
      Arn: string;
      Direction: string;
      HostVPCId: string;
      IpAddressCount: string;
      Name: string;
      OutpostArn: string;
      PreferredInstanceType: string;
      ResolverEndpointId: string;
    }
    export interface IpAddressRequest {
      Ip?: string;
      SubnetId: string;
    }
  }
  export interface ResolverQueryLoggingConfig {
    DestinationArn?: string;
    Name?: string;
  }
  export interface ResolverQueryLoggingConfigAssociation {
    ResolverQueryLogConfigId?: string;
    ResourceId?: string;
  }
  export interface ResolverRule {
    DomainName: string;
    Name?: string;
    ResolverEndpointId?: string;
    RuleType: string;
    Tags?: Tag[];
    TargetIps?: ResolverRule.TargetAddress[];
  }
  export namespace ResolverRule {
    export interface Attr {
      Arn: string;
      DomainName: string;
      Name: string;
      ResolverEndpointId: string;
      ResolverRuleId: string;
      TargetIps: TargetAddress[];
    }
    export interface TargetAddress {
      Ip: string;
      Port?: string;
    }
  }
  export interface ResolverRuleAssociation {
    Name?: string;
    ResolverRuleId: string;
    VPCId: string;
  }
}
export namespace S3 {
  export interface AccessPoint {
    Bucket: string;
    BucketAccountId?: string;
    Name?: string;
    Policy?: any;
    PolicyStatus?: any;
    PublicAccessBlockConfiguration?: AccessPoint.PublicAccessBlockConfiguration;
    VpcConfiguration?: AccessPoint.VpcConfiguration;
  }
  export namespace AccessPoint {
    export interface Attr {
      Alias: string;
      Arn: string;
      Name: string;
      NetworkOrigin: string;
    }
    export interface PolicyStatus {
      IsPublic?: string;
    }
    export interface PublicAccessBlockConfiguration {
      BlockPublicAcls?: boolean;
      BlockPublicPolicy?: boolean;
      IgnorePublicAcls?: boolean;
      RestrictPublicBuckets?: boolean;
    }
    export interface VpcConfiguration {
      VpcId?: string;
    }
  }
  export interface Bucket {
    AccelerateConfiguration?: Bucket.AccelerateConfiguration;
    AccessControl?: string;
    AnalyticsConfigurations?: Bucket.AnalyticsConfiguration[];
    BucketEncryption?: Bucket.BucketEncryption;
    BucketName?: string;
    CorsConfiguration?: Bucket.CorsConfiguration;
    IntelligentTieringConfigurations?: Bucket.IntelligentTieringConfiguration[];
    InventoryConfigurations?: Bucket.InventoryConfiguration[];
    LifecycleConfiguration?: Bucket.LifecycleConfiguration;
    LoggingConfiguration?: Bucket.LoggingConfiguration;
    MetricsConfigurations?: Bucket.MetricsConfiguration[];
    NotificationConfiguration?: Bucket.NotificationConfiguration;
    ObjectLockConfiguration?: Bucket.ObjectLockConfiguration;
    ObjectLockEnabled?: boolean;
    OwnershipControls?: Bucket.OwnershipControls;
    PublicAccessBlockConfiguration?: Bucket.PublicAccessBlockConfiguration;
    ReplicationConfiguration?: Bucket.ReplicationConfiguration;
    Tags?: Tag[];
    VersioningConfiguration?: Bucket.VersioningConfiguration;
    WebsiteConfiguration?: Bucket.WebsiteConfiguration;
  }
  export namespace Bucket {
    export interface Attr {
      Arn: string;
      DomainName: string;
      DualStackDomainName: string;
      RegionalDomainName: string;
      WebsiteURL: string;
    }
    export interface AbortIncompleteMultipartUpload {
      DaysAfterInitiation: number;
    }
    export interface AccelerateConfiguration {
      AccelerationStatus: string;
    }
    export interface AccessControlTranslation {
      Owner: string;
    }
    export interface AnalyticsConfiguration {
      Id: string;
      Prefix?: string;
      StorageClassAnalysis: StorageClassAnalysis;
      TagFilters?: TagFilter[];
    }
    export interface BucketEncryption {
      ServerSideEncryptionConfiguration: ServerSideEncryptionRule[];
    }
    export interface CorsConfiguration {
      CorsRules: CorsRule[];
    }
    export interface CorsRule {
      AllowedHeaders?: string[];
      AllowedMethods: string[];
      AllowedOrigins: string[];
      ExposedHeaders?: string[];
      Id?: string;
      MaxAge?: number;
    }
    export interface DataExport {
      Destination: Destination;
      OutputSchemaVersion: string;
    }
    export interface DefaultRetention {
      Days?: number;
      Mode?: string;
      Years?: number;
    }
    export interface DeleteMarkerReplication {
      Status?: string;
    }
    export interface Destination {
      BucketAccountId?: string;
      BucketArn: string;
      Format: string;
      Prefix?: string;
    }
    export interface EncryptionConfiguration {
      ReplicaKmsKeyID: string;
    }
    export interface EventBridgeConfiguration {
      EventBridgeEnabled?: boolean;
    }
    export interface FilterRule {
      Name: string;
      Value: string;
    }
    export interface IntelligentTieringConfiguration {
      Id: string;
      Prefix?: string;
      Status: string;
      TagFilters?: TagFilter[];
      Tierings: Tiering[];
    }
    export interface InventoryConfiguration {
      Destination: Destination;
      Enabled: boolean;
      Id: string;
      IncludedObjectVersions: string;
      OptionalFields?: string[];
      Prefix?: string;
      ScheduleFrequency: string;
    }
    export interface LambdaConfiguration {
      Event: string;
      Filter?: NotificationFilter;
      Function: string;
    }
    export interface LifecycleConfiguration {
      Rules: Rule[];
    }
    export interface LoggingConfiguration {
      DestinationBucketName?: string;
      LogFilePrefix?: string;
    }
    export interface Metrics {
      EventThreshold?: ReplicationTimeValue;
      Status: string;
    }
    export interface MetricsConfiguration {
      AccessPointArn?: string;
      Id: string;
      Prefix?: string;
      TagFilters?: TagFilter[];
    }
    export interface NoncurrentVersionExpiration {
      NewerNoncurrentVersions?: number;
      NoncurrentDays: number;
    }
    export interface NoncurrentVersionTransition {
      NewerNoncurrentVersions?: number;
      StorageClass: string;
      TransitionInDays: number;
    }
    export interface NotificationConfiguration {
      EventBridgeConfiguration?: EventBridgeConfiguration;
      LambdaConfigurations?: LambdaConfiguration[];
      QueueConfigurations?: QueueConfiguration[];
      TopicConfigurations?: TopicConfiguration[];
    }
    export interface NotificationFilter {
      S3Key: S3KeyFilter;
    }
    export interface ObjectLockConfiguration {
      ObjectLockEnabled?: string;
      Rule?: ObjectLockRule;
    }
    export interface ObjectLockRule {
      DefaultRetention?: DefaultRetention;
    }
    export interface OwnershipControls {
      Rules: OwnershipControlsRule[];
    }
    export interface OwnershipControlsRule {
      ObjectOwnership?: string;
    }
    export interface PublicAccessBlockConfiguration {
      BlockPublicAcls?: boolean;
      BlockPublicPolicy?: boolean;
      IgnorePublicAcls?: boolean;
      RestrictPublicBuckets?: boolean;
    }
    export interface QueueConfiguration {
      Event: string;
      Filter?: NotificationFilter;
      Queue: string;
    }
    export interface RedirectAllRequestsTo {
      HostName: string;
      Protocol?: string;
    }
    export interface RedirectRule {
      HostName?: string;
      HttpRedirectCode?: string;
      Protocol?: string;
      ReplaceKeyPrefixWith?: string;
      ReplaceKeyWith?: string;
    }
    export interface ReplicaModifications {
      Status: string;
    }
    export interface ReplicationConfiguration {
      Role: string;
      Rules: ReplicationRule[];
    }
    export interface ReplicationDestination {
      AccessControlTranslation?: AccessControlTranslation;
      Account?: string;
      Bucket: string;
      EncryptionConfiguration?: EncryptionConfiguration;
      Metrics?: Metrics;
      ReplicationTime?: ReplicationTime;
      StorageClass?: string;
    }
    export interface ReplicationRule {
      DeleteMarkerReplication?: DeleteMarkerReplication;
      Destination: ReplicationDestination;
      Filter?: ReplicationRuleFilter;
      Id?: string;
      Prefix?: string;
      Priority?: number;
      SourceSelectionCriteria?: SourceSelectionCriteria;
      Status: string;
    }
    export interface ReplicationRuleAndOperator {
      Prefix?: string;
      TagFilters?: TagFilter[];
    }
    export interface ReplicationRuleFilter {
      And?: ReplicationRuleAndOperator;
      Prefix?: string;
      TagFilter?: TagFilter;
    }
    export interface ReplicationTime {
      Status: string;
      Time: ReplicationTimeValue;
    }
    export interface ReplicationTimeValue {
      Minutes: number;
    }
    export interface RoutingRule {
      RedirectRule: RedirectRule;
      RoutingRuleCondition?: RoutingRuleCondition;
    }
    export interface RoutingRuleCondition {
      HttpErrorCodeReturnedEquals?: string;
      KeyPrefixEquals?: string;
    }
    export interface Rule {
      AbortIncompleteMultipartUpload?: AbortIncompleteMultipartUpload;
      ExpirationDate?: string;
      ExpirationInDays?: number;
      ExpiredObjectDeleteMarker?: boolean;
      Id?: string;
      NoncurrentVersionExpiration?: NoncurrentVersionExpiration;
      NoncurrentVersionExpirationInDays?: number;
      NoncurrentVersionTransition?: NoncurrentVersionTransition;
      NoncurrentVersionTransitions?: NoncurrentVersionTransition[];
      ObjectSizeGreaterThan?: number;
      ObjectSizeLessThan?: number;
      Prefix?: string;
      Status: string;
      TagFilters?: TagFilter[];
      Transition?: Transition;
      Transitions?: Transition[];
    }
    export interface S3KeyFilter {
      Rules: FilterRule[];
    }
    export interface ServerSideEncryptionByDefault {
      KMSMasterKeyID?: string;
      SSEAlgorithm: string;
    }
    export interface ServerSideEncryptionRule {
      BucketKeyEnabled?: boolean;
      ServerSideEncryptionByDefault?: ServerSideEncryptionByDefault;
    }
    export interface SourceSelectionCriteria {
      ReplicaModifications?: ReplicaModifications;
      SseKmsEncryptedObjects?: SseKmsEncryptedObjects;
    }
    export interface SseKmsEncryptedObjects {
      Status: string;
    }
    export interface StorageClassAnalysis {
      DataExport?: DataExport;
    }
    export interface TagFilter {
      Key: string;
      Value: string;
    }
    export interface Tiering {
      AccessTier: string;
      Days: number;
    }
    export interface TopicConfiguration {
      Event: string;
      Filter?: NotificationFilter;
      Topic: string;
    }
    export interface Transition {
      StorageClass: string;
      TransitionDate?: string;
      TransitionInDays?: number;
    }
    export interface VersioningConfiguration {
      Status: string;
    }
    export interface WebsiteConfiguration {
      ErrorDocument?: string;
      IndexDocument?: string;
      RedirectAllRequestsTo?: RedirectAllRequestsTo;
      RoutingRules?: RoutingRule[];
    }
  }
  export interface BucketPolicy {
    Bucket: string;
    PolicyDocument: any;
  }
  export interface MultiRegionAccessPoint {
    Name?: string;
    PublicAccessBlockConfiguration?: MultiRegionAccessPoint.PublicAccessBlockConfiguration;
    Regions: MultiRegionAccessPoint.Region[];
  }
  export namespace MultiRegionAccessPoint {
    export interface Attr {
      Alias: string;
      CreatedAt: string;
    }
    export interface PublicAccessBlockConfiguration {
      BlockPublicAcls?: boolean;
      BlockPublicPolicy?: boolean;
      IgnorePublicAcls?: boolean;
      RestrictPublicBuckets?: boolean;
    }
    export interface Region {
      Bucket: string;
    }
  }
  export interface MultiRegionAccessPointPolicy {
    MrapName: string;
    Policy: any;
  }
  export namespace MultiRegionAccessPointPolicy {
    export interface Attr {
      "PolicyStatus.IsPublic": string;
    }
    export interface PolicyStatus {
      IsPublic: string;
    }
  }
  export interface StorageLens {
    StorageLensConfiguration: StorageLens.StorageLensConfiguration;
    Tags?: Tag[];
  }
  export namespace StorageLens {
    export interface Attr {
      "StorageLensConfiguration.StorageLensArn": string;
    }
    export interface AccountLevel {
      ActivityMetrics?: ActivityMetrics;
      AdvancedCostOptimizationMetrics?: AdvancedCostOptimizationMetrics;
      AdvancedDataProtectionMetrics?: AdvancedDataProtectionMetrics;
      BucketLevel: BucketLevel;
      DetailedStatusCodesMetrics?: DetailedStatusCodesMetrics;
    }
    export interface ActivityMetrics {
      IsEnabled?: boolean;
    }
    export interface AdvancedCostOptimizationMetrics {
      IsEnabled?: boolean;
    }
    export interface AdvancedDataProtectionMetrics {
      IsEnabled?: boolean;
    }
    export interface AwsOrg {
      Arn: string;
    }
    export interface BucketLevel {
      ActivityMetrics?: ActivityMetrics;
      AdvancedCostOptimizationMetrics?: AdvancedCostOptimizationMetrics;
      AdvancedDataProtectionMetrics?: AdvancedDataProtectionMetrics;
      DetailedStatusCodesMetrics?: DetailedStatusCodesMetrics;
      PrefixLevel?: PrefixLevel;
    }
    export interface BucketsAndRegions {
      Buckets?: string[];
      Regions?: string[];
    }
    export interface CloudWatchMetrics {
      IsEnabled: boolean;
    }
    export interface DataExport {
      CloudWatchMetrics?: CloudWatchMetrics;
      S3BucketDestination?: S3BucketDestination;
    }
    export interface DetailedStatusCodesMetrics {
      IsEnabled?: boolean;
    }
    export interface Encryption {
      SSEKMS?: SSEKMS;
      SSES3?: any;
    }
    export interface PrefixLevel {
      StorageMetrics: PrefixLevelStorageMetrics;
    }
    export interface PrefixLevelStorageMetrics {
      IsEnabled?: boolean;
      SelectionCriteria?: SelectionCriteria;
    }
    export interface S3BucketDestination {
      AccountId: string;
      Arn: string;
      Encryption?: Encryption;
      Format: string;
      OutputSchemaVersion: string;
      Prefix?: string;
    }
    export interface SSEKMS {
      KeyId: string;
    }
    export interface SelectionCriteria {
      Delimiter?: string;
      MaxDepth?: number;
      MinStorageBytesPercentage?: number;
    }
    export interface StorageLensConfiguration {
      AccountLevel: AccountLevel;
      AwsOrg?: AwsOrg;
      DataExport?: DataExport;
      Exclude?: BucketsAndRegions;
      Id: string;
      Include?: BucketsAndRegions;
      IsEnabled: boolean;
      StorageLensArn?: string;
    }
  }
}
export namespace S3ObjectLambda {
  export interface AccessPoint {
    Name?: string;
    ObjectLambdaConfiguration: AccessPoint.ObjectLambdaConfiguration;
  }
  export namespace AccessPoint {
    export interface Attr {
      Arn: string;
      CreationDate: string;
      "PolicyStatus.IsPublic": boolean;
      "PublicAccessBlockConfiguration.BlockPublicAcls": boolean;
      "PublicAccessBlockConfiguration.BlockPublicPolicy": boolean;
      "PublicAccessBlockConfiguration.IgnorePublicAcls": boolean;
      "PublicAccessBlockConfiguration.RestrictPublicBuckets": boolean;
    }
    export interface AwsLambda {
      FunctionArn: string;
      FunctionPayload?: string;
    }
    export interface ContentTransformation {
      AwsLambda: AwsLambda;
    }
    export interface ObjectLambdaConfiguration {
      AllowedFeatures?: string[];
      CloudWatchMetricsEnabled?: boolean;
      SupportingAccessPoint: string;
      TransformationConfigurations: TransformationConfiguration[];
    }
    export interface PolicyStatus {
      IsPublic?: boolean;
    }
    export interface PublicAccessBlockConfiguration {
      BlockPublicAcls?: boolean;
      BlockPublicPolicy?: boolean;
      IgnorePublicAcls?: boolean;
      RestrictPublicBuckets?: boolean;
    }
    export interface TransformationConfiguration {
      Actions: string[];
      ContentTransformation: any;
    }
  }
  export interface AccessPointPolicy {
    ObjectLambdaAccessPoint: string;
    PolicyDocument: any;
  }
}
export namespace S3Outposts {
  export interface AccessPoint {
    Bucket: string;
    Name: string;
    Policy?: any;
    VpcConfiguration: AccessPoint.VpcConfiguration;
  }
  export namespace AccessPoint {
    export interface Attr {
      Arn: string;
    }
    export interface VpcConfiguration {
      VpcId?: string;
    }
  }
  export interface Bucket {
    BucketName: string;
    LifecycleConfiguration?: Bucket.LifecycleConfiguration;
    OutpostId: string;
    Tags?: Tag[];
  }
  export namespace Bucket {
    export interface Attr {
      Arn: string;
    }
    export interface AbortIncompleteMultipartUpload {
      DaysAfterInitiation: number;
    }
    export interface Filter {
      AndOperator?: FilterAndOperator;
      Prefix?: string;
      Tag?: FilterTag;
    }
    export interface FilterAndOperator {
      Prefix?: string;
      Tags: FilterTag[];
    }
    export interface FilterTag {
      Key: string;
      Value: string;
    }
    export interface LifecycleConfiguration {
      Rules: Rule[];
    }
    export interface Rule {
      AbortIncompleteMultipartUpload?: AbortIncompleteMultipartUpload;
      ExpirationDate?: string;
      ExpirationInDays?: number;
      Filter?: any;
      Id?: string;
      Status: string;
    }
  }
  export interface BucketPolicy {
    Bucket: string;
    PolicyDocument: any;
  }
  export interface Endpoint {
    AccessType?: string;
    CustomerOwnedIpv4Pool?: string;
    OutpostId: string;
    SecurityGroupId: string;
    SubnetId: string;
  }
  export namespace Endpoint {
    export interface Attr {
      Arn: string;
      CidrBlock: string;
      CreationTime: string;
      Id: string;
      NetworkInterfaces: NetworkInterface[];
      Status: string;
    }
    export interface NetworkInterface {
      NetworkInterfaceId: string;
    }
  }
}
export namespace SDB {
  export interface Domain {
    Description?: string;
  }
}
export namespace SES {
  export interface ConfigurationSet {
    DeliveryOptions?: ConfigurationSet.DeliveryOptions;
    Name?: string;
    ReputationOptions?: ConfigurationSet.ReputationOptions;
    SendingOptions?: ConfigurationSet.SendingOptions;
    SuppressionOptions?: ConfigurationSet.SuppressionOptions;
    TrackingOptions?: ConfigurationSet.TrackingOptions;
    VdmOptions?: ConfigurationSet.VdmOptions;
  }
  export namespace ConfigurationSet {
    export interface Attr {}
    export interface DashboardOptions {
      EngagementMetrics: string;
    }
    export interface DeliveryOptions {
      SendingPoolName?: string;
      TlsPolicy?: string;
    }
    export interface GuardianOptions {
      OptimizedSharedDelivery: string;
    }
    export interface ReputationOptions {
      ReputationMetricsEnabled?: boolean;
    }
    export interface SendingOptions {
      SendingEnabled?: boolean;
    }
    export interface SuppressionOptions {
      SuppressedReasons?: string[];
    }
    export interface TrackingOptions {
      CustomRedirectDomain?: string;
    }
    export interface VdmOptions {
      DashboardOptions?: DashboardOptions;
      GuardianOptions?: GuardianOptions;
    }
  }
  export interface ConfigurationSetEventDestination {
    ConfigurationSetName: string;
    EventDestination: ConfigurationSetEventDestination.EventDestination;
  }
  export namespace ConfigurationSetEventDestination {
    export interface Attr {
      Id: string;
    }
    export interface CloudWatchDestination {
      DimensionConfigurations?: DimensionConfiguration[];
    }
    export interface DimensionConfiguration {
      DefaultDimensionValue: string;
      DimensionName: string;
      DimensionValueSource: string;
    }
    export interface EventDestination {
      CloudWatchDestination?: CloudWatchDestination;
      Enabled?: boolean;
      KinesisFirehoseDestination?: KinesisFirehoseDestination;
      MatchingEventTypes: string[];
      Name?: string;
      SnsDestination?: SnsDestination;
    }
    export interface KinesisFirehoseDestination {
      DeliveryStreamARN: string;
      IAMRoleARN: string;
    }
    export interface SnsDestination {
      TopicARN: string;
    }
  }
  export interface ContactList {
    ContactListName?: string;
    Description?: string;
    Tags?: Tag[];
    Topics?: ContactList.Topic[];
  }
  export namespace ContactList {
    export interface Attr {}
    export interface Topic {
      DefaultSubscriptionStatus: string;
      Description?: string;
      DisplayName: string;
      TopicName: string;
    }
  }
  export interface DedicatedIpPool {
    PoolName?: string;
    ScalingMode?: string;
  }
  export interface EmailIdentity {
    ConfigurationSetAttributes?: EmailIdentity.ConfigurationSetAttributes;
    DkimAttributes?: EmailIdentity.DkimAttributes;
    DkimSigningAttributes?: EmailIdentity.DkimSigningAttributes;
    EmailIdentity: string;
    FeedbackAttributes?: EmailIdentity.FeedbackAttributes;
    MailFromAttributes?: EmailIdentity.MailFromAttributes;
  }
  export namespace EmailIdentity {
    export interface Attr {
      DkimDNSTokenName1: string;
      DkimDNSTokenName2: string;
      DkimDNSTokenName3: string;
      DkimDNSTokenValue1: string;
      DkimDNSTokenValue2: string;
      DkimDNSTokenValue3: string;
    }
    export interface ConfigurationSetAttributes {
      ConfigurationSetName?: string;
    }
    export interface DkimAttributes {
      SigningEnabled?: boolean;
    }
    export interface DkimSigningAttributes {
      DomainSigningPrivateKey?: string;
      DomainSigningSelector?: string;
      NextSigningKeyLength?: string;
    }
    export interface FeedbackAttributes {
      EmailForwardingEnabled?: boolean;
    }
    export interface MailFromAttributes {
      BehaviorOnMxFailure?: string;
      MailFromDomain?: string;
    }
  }
  export interface ReceiptFilter {
    Filter: ReceiptFilter.Filter;
  }
  export namespace ReceiptFilter {
    export interface Attr {}
    export interface Filter {
      IpFilter: IpFilter;
      Name?: string;
    }
    export interface IpFilter {
      Cidr: string;
      Policy: string;
    }
  }
  export interface ReceiptRule {
    After?: string;
    Rule: ReceiptRule.Rule;
    RuleSetName: string;
  }
  export namespace ReceiptRule {
    export interface Attr {}
    export interface Action {
      AddHeaderAction?: AddHeaderAction;
      BounceAction?: BounceAction;
      LambdaAction?: LambdaAction;
      S3Action?: S3Action;
      SNSAction?: SNSAction;
      StopAction?: StopAction;
      WorkmailAction?: WorkmailAction;
    }
    export interface AddHeaderAction {
      HeaderName: string;
      HeaderValue: string;
    }
    export interface BounceAction {
      Message: string;
      Sender: string;
      SmtpReplyCode: string;
      StatusCode?: string;
      TopicArn?: string;
    }
    export interface LambdaAction {
      FunctionArn: string;
      InvocationType?: string;
      TopicArn?: string;
    }
    export interface Rule {
      Actions?: Action[];
      Enabled?: boolean;
      Name?: string;
      Recipients?: string[];
      ScanEnabled?: boolean;
      TlsPolicy?: string;
    }
    export interface S3Action {
      BucketName: string;
      KmsKeyArn?: string;
      ObjectKeyPrefix?: string;
      TopicArn?: string;
    }
    export interface SNSAction {
      Encoding?: string;
      TopicArn?: string;
    }
    export interface StopAction {
      Scope: string;
      TopicArn?: string;
    }
    export interface WorkmailAction {
      OrganizationArn: string;
      TopicArn?: string;
    }
  }
  export interface ReceiptRuleSet {
    RuleSetName?: string;
  }
  export interface Template {
    Template?: Template.Template;
  }
  export namespace Template {
    export interface Attr {
      Id: string;
    }
    export interface Template {
      HtmlPart?: string;
      SubjectPart: string;
      TemplateName?: string;
      TextPart?: string;
    }
  }
  export interface VdmAttributes {
    DashboardAttributes?: VdmAttributes.DashboardAttributes;
    GuardianAttributes?: VdmAttributes.GuardianAttributes;
  }
  export namespace VdmAttributes {
    export interface Attr {
      VdmAttributesResourceId: string;
    }
    export interface DashboardAttributes {
      EngagementMetrics?: string;
    }
    export interface GuardianAttributes {
      OptimizedSharedDelivery?: string;
    }
  }
}
export namespace SNS {
  export interface Subscription {
    DeliveryPolicy?: any;
    Endpoint?: string;
    FilterPolicy?: any;
    FilterPolicyScope?: string;
    Protocol: string;
    RawMessageDelivery?: boolean;
    RedrivePolicy?: any;
    Region?: string;
    SubscriptionRoleArn?: string;
    TopicArn: string;
  }
  export interface Topic {
    ContentBasedDeduplication?: boolean;
    DataProtectionPolicy?: any;
    DisplayName?: string;
    FifoTopic?: boolean;
    KmsMasterKeyId?: string;
    SignatureVersion?: string;
    Subscription?: Topic.Subscription[];
    Tags?: Tag[];
    TopicName?: string;
  }
  export namespace Topic {
    export interface Attr {
      TopicArn: string;
      TopicName: string;
    }
    export interface Subscription {
      Endpoint: string;
      Protocol: string;
    }
  }
  export interface TopicPolicy {
    PolicyDocument: any;
    Topics: string[];
  }
}
export namespace SQS {
  export interface Queue {
    ContentBasedDeduplication?: boolean;
    DeduplicationScope?: string;
    DelaySeconds?: number;
    FifoQueue?: boolean;
    FifoThroughputLimit?: string;
    KmsDataKeyReusePeriodSeconds?: number;
    KmsMasterKeyId?: string;
    MaximumMessageSize?: number;
    MessageRetentionPeriod?: number;
    QueueName?: string;
    ReceiveMessageWaitTimeSeconds?: number;
    RedriveAllowPolicy?: any;
    RedrivePolicy?: any;
    SqsManagedSseEnabled?: boolean;
    Tags?: Tag[];
    VisibilityTimeout?: number;
  }
  export interface QueuePolicy {
    PolicyDocument: any;
    Queues: string[];
  }
}
export namespace SSM {
  export interface Association {
    ApplyOnlyAtCronInterval?: boolean;
    AssociationName?: string;
    AutomationTargetParameterName?: string;
    CalendarNames?: string[];
    ComplianceSeverity?: string;
    DocumentVersion?: string;
    InstanceId?: string;
    MaxConcurrency?: string;
    MaxErrors?: string;
    Name: string;
    OutputLocation?: Association.InstanceAssociationOutputLocation;
    Parameters?: any;
    ScheduleExpression?: string;
    ScheduleOffset?: number;
    SyncCompliance?: string;
    Targets?: Association.Target[];
    WaitForSuccessTimeoutSeconds?: number;
  }
  export namespace Association {
    export interface Attr {
      AssociationId: string;
    }
    export interface InstanceAssociationOutputLocation {
      S3Location?: S3OutputLocation;
    }
    export interface S3OutputLocation {
      OutputS3BucketName?: string;
      OutputS3KeyPrefix?: string;
      OutputS3Region?: string;
    }
    export interface Target {
      Key: string;
      Values: string[];
    }
  }
  export interface Document {
    Attachments?: Document.AttachmentsSource[];
    Content: any;
    DocumentFormat?: string;
    DocumentType?: string;
    Name?: string;
    Requires?: Document.DocumentRequires[];
    Tags?: Tag[];
    TargetType?: string;
    UpdateMethod?: string;
    VersionName?: string;
  }
  export namespace Document {
    export interface Attr {}
    export interface AttachmentsSource {
      Key?: string;
      Name?: string;
      Values?: string[];
    }
    export interface DocumentRequires {
      Name?: string;
      Version?: string;
    }
  }
  export interface MaintenanceWindow {
    AllowUnassociatedTargets: boolean;
    Cutoff: number;
    Description?: string;
    Duration: number;
    EndDate?: string;
    Name: string;
    Schedule: string;
    ScheduleOffset?: number;
    ScheduleTimezone?: string;
    StartDate?: string;
    Tags?: Tag[];
  }
  export interface MaintenanceWindowTarget {
    Description?: string;
    Name?: string;
    OwnerInformation?: string;
    ResourceType: string;
    Targets: MaintenanceWindowTarget.Targets[];
    WindowId: string;
  }
  export namespace MaintenanceWindowTarget {
    export interface Attr {}
    export interface Targets {
      Key: string;
      Values: string[];
    }
  }
  export interface MaintenanceWindowTask {
    CutoffBehavior?: string;
    Description?: string;
    LoggingInfo?: MaintenanceWindowTask.LoggingInfo;
    MaxConcurrency?: string;
    MaxErrors?: string;
    Name?: string;
    Priority: number;
    ServiceRoleArn?: string;
    Targets?: MaintenanceWindowTask.Target[];
    TaskArn: string;
    TaskInvocationParameters?: MaintenanceWindowTask.TaskInvocationParameters;
    TaskParameters?: any;
    TaskType: string;
    WindowId: string;
  }
  export namespace MaintenanceWindowTask {
    export interface Attr {}
    export interface CloudWatchOutputConfig {
      CloudWatchLogGroupName?: string;
      CloudWatchOutputEnabled?: boolean;
    }
    export interface LoggingInfo {
      Region: string;
      S3Bucket: string;
      S3Prefix?: string;
    }
    export interface MaintenanceWindowAutomationParameters {
      DocumentVersion?: string;
      Parameters?: any;
    }
    export interface MaintenanceWindowLambdaParameters {
      ClientContext?: string;
      Payload?: string;
      Qualifier?: string;
    }
    export interface MaintenanceWindowRunCommandParameters {
      CloudWatchOutputConfig?: CloudWatchOutputConfig;
      Comment?: string;
      DocumentHash?: string;
      DocumentHashType?: string;
      DocumentVersion?: string;
      NotificationConfig?: NotificationConfig;
      OutputS3BucketName?: string;
      OutputS3KeyPrefix?: string;
      Parameters?: any;
      ServiceRoleArn?: string;
      TimeoutSeconds?: number;
    }
    export interface MaintenanceWindowStepFunctionsParameters {
      Input?: string;
      Name?: string;
    }
    export interface NotificationConfig {
      NotificationArn: string;
      NotificationEvents?: string[];
      NotificationType?: string;
    }
    export interface Target {
      Key: string;
      Values: string[];
    }
    export interface TaskInvocationParameters {
      MaintenanceWindowAutomationParameters?: MaintenanceWindowAutomationParameters;
      MaintenanceWindowLambdaParameters?: MaintenanceWindowLambdaParameters;
      MaintenanceWindowRunCommandParameters?: MaintenanceWindowRunCommandParameters;
      MaintenanceWindowStepFunctionsParameters?: MaintenanceWindowStepFunctionsParameters;
    }
  }
  export interface Parameter {
    AllowedPattern?: string;
    DataType?: string;
    Description?: string;
    Name?: string;
    Policies?: string;
    Tags?: any;
    Tier?: string;
    Type: string;
    Value: string;
  }
  export interface PatchBaseline {
    ApprovalRules?: PatchBaseline.RuleGroup;
    ApprovedPatches?: string[];
    ApprovedPatchesComplianceLevel?: string;
    ApprovedPatchesEnableNonSecurity?: boolean;
    Description?: string;
    GlobalFilters?: PatchBaseline.PatchFilterGroup;
    Name: string;
    OperatingSystem?: string;
    PatchGroups?: string[];
    RejectedPatches?: string[];
    RejectedPatchesAction?: string;
    Sources?: PatchBaseline.PatchSource[];
    Tags?: Tag[];
  }
  export namespace PatchBaseline {
    export interface Attr {}
    export interface PatchFilter {
      Key?: string;
      Values?: string[];
    }
    export interface PatchFilterGroup {
      PatchFilters?: PatchFilter[];
    }
    export interface PatchSource {
      Configuration?: string;
      Name?: string;
      Products?: string[];
    }
    export interface PatchStringDate {}
    export interface Rule {
      ApproveAfterDays?: number;
      ApproveUntilDate?: PatchStringDate;
      ComplianceLevel?: string;
      EnableNonSecurity?: boolean;
      PatchFilterGroup?: PatchFilterGroup;
    }
    export interface RuleGroup {
      PatchRules?: Rule[];
    }
  }
  export interface ResourceDataSync {
    BucketName?: string;
    BucketPrefix?: string;
    BucketRegion?: string;
    KMSKeyArn?: string;
    S3Destination?: ResourceDataSync.S3Destination;
    SyncFormat?: string;
    SyncName: string;
    SyncSource?: ResourceDataSync.SyncSource;
    SyncType?: string;
  }
  export namespace ResourceDataSync {
    export interface Attr {
      SyncName: string;
    }
    export interface AwsOrganizationsSource {
      OrganizationSourceType: string;
      OrganizationalUnits?: string[];
    }
    export interface S3Destination {
      BucketName: string;
      BucketPrefix?: string;
      BucketRegion: string;
      KMSKeyArn?: string;
      SyncFormat: string;
    }
    export interface SyncSource {
      AwsOrganizationsSource?: AwsOrganizationsSource;
      IncludeFutureRegions?: boolean;
      SourceRegions: string[];
      SourceType: string;
    }
  }
  export interface ResourcePolicy {
    Policy: any;
    ResourceArn: string;
  }
}
export namespace SSMContacts {
  export interface Contact {
    Alias: string;
    DisplayName: string;
    Plan: Contact.Stage[];
    Type: string;
  }
  export namespace Contact {
    export interface Attr {
      Arn: string;
    }
    export interface ChannelTargetInfo {
      ChannelId: string;
      RetryIntervalInMinutes: number;
    }
    export interface ContactTargetInfo {
      ContactId: string;
      IsEssential: boolean;
    }
    export interface Stage {
      DurationInMinutes: number;
      Targets?: Targets[];
    }
    export interface Targets {
      ChannelTargetInfo?: ChannelTargetInfo;
      ContactTargetInfo?: ContactTargetInfo;
    }
  }
  export interface ContactChannel {
    ChannelAddress: string;
    ChannelName: string;
    ChannelType: string;
    ContactId: string;
    DeferActivation?: boolean;
  }
}
export namespace SSMIncidents {
  export interface ReplicationSet {
    DeletionProtected?: boolean;
    Regions: ReplicationSet.ReplicationRegion[];
    Tags?: Tag[];
  }
  export namespace ReplicationSet {
    export interface Attr {
      Arn: string;
    }
    export interface RegionConfiguration {
      SseKmsKeyId: string;
    }
    export interface ReplicationRegion {
      RegionConfiguration?: RegionConfiguration;
      RegionName?: string;
    }
  }
  export interface ResponsePlan {
    Actions?: ResponsePlan.Action[];
    ChatChannel?: ResponsePlan.ChatChannel;
    DisplayName?: string;
    Engagements?: string[];
    IncidentTemplate: ResponsePlan.IncidentTemplate;
    Integrations?: ResponsePlan.Integration[];
    Name: string;
    Tags?: Tag[];
  }
  export namespace ResponsePlan {
    export interface Attr {
      Arn: string;
    }
    export interface Action {
      SsmAutomation?: SsmAutomation;
    }
    export interface ChatChannel {
      ChatbotSns?: string[];
    }
    export interface DynamicSsmParameter {
      Key: string;
      Value: DynamicSsmParameterValue;
    }
    export interface DynamicSsmParameterValue {
      Variable?: string;
    }
    export interface IncidentTemplate {
      DedupeString?: string;
      Impact: number;
      IncidentTags?: Tag[];
      NotificationTargets?: NotificationTargetItem[];
      Summary?: string;
      Title: string;
    }
    export interface Integration {
      PagerDutyConfiguration: PagerDutyConfiguration;
    }
    export interface NotificationTargetItem {
      SnsTopicArn?: string;
    }
    export interface PagerDutyConfiguration {
      Name: string;
      PagerDutyIncidentConfiguration: PagerDutyIncidentConfiguration;
      SecretId: string;
    }
    export interface PagerDutyIncidentConfiguration {
      ServiceId: string;
    }
    export interface SsmAutomation {
      DocumentName: string;
      DocumentVersion?: string;
      DynamicParameters?: DynamicSsmParameter[];
      Parameters?: SsmParameter[];
      RoleArn: string;
      TargetAccount?: string;
    }
    export interface SsmParameter {
      Key: string;
      Values: string[];
    }
  }
}
export namespace SSO {
  export interface Assignment {
    InstanceArn: string;
    PermissionSetArn: string;
    PrincipalId: string;
    PrincipalType: string;
    TargetId: string;
    TargetType: string;
  }
  export interface InstanceAccessControlAttributeConfiguration {
    AccessControlAttributes?: InstanceAccessControlAttributeConfiguration.AccessControlAttribute[];
    InstanceArn: string;
  }
  export namespace InstanceAccessControlAttributeConfiguration {
    export interface Attr {}
    export interface AccessControlAttribute {
      Key: string;
      Value: AccessControlAttributeValue;
    }
    export interface AccessControlAttributeValue {
      Source: string[];
    }
  }
  export interface PermissionSet {
    CustomerManagedPolicyReferences?: PermissionSet.CustomerManagedPolicyReference[];
    Description?: string;
    InlinePolicy?: any;
    InstanceArn: string;
    ManagedPolicies?: string[];
    Name: string;
    PermissionsBoundary?: PermissionSet.PermissionsBoundary;
    RelayStateType?: string;
    SessionDuration?: string;
    Tags?: Tag[];
  }
  export namespace PermissionSet {
    export interface Attr {
      PermissionSetArn: string;
    }
    export interface CustomerManagedPolicyReference {
      Name: string;
      Path?: string;
    }
    export interface PermissionsBoundary {
      CustomerManagedPolicyReference?: CustomerManagedPolicyReference;
      ManagedPolicyArn?: string;
    }
  }
}
export namespace SageMaker {
  export interface App {
    AppName: string;
    AppType: string;
    DomainId: string;
    ResourceSpec?: App.ResourceSpec;
    Tags?: Tag[];
    UserProfileName: string;
  }
  export namespace App {
    export interface Attr {
      AppArn: string;
    }
    export interface ResourceSpec {
      InstanceType?: string;
      SageMakerImageArn?: string;
      SageMakerImageVersionArn?: string;
    }
  }
  export interface AppImageConfig {
    AppImageConfigName: string;
    KernelGatewayImageConfig?: AppImageConfig.KernelGatewayImageConfig;
    Tags?: Tag[];
  }
  export namespace AppImageConfig {
    export interface Attr {
      AppImageConfigArn: string;
    }
    export interface FileSystemConfig {
      DefaultGid?: number;
      DefaultUid?: number;
      MountPath?: string;
    }
    export interface KernelGatewayImageConfig {
      FileSystemConfig?: FileSystemConfig;
      KernelSpecs: KernelSpec[];
    }
    export interface KernelSpec {
      DisplayName?: string;
      Name: string;
    }
  }
  export interface CodeRepository {
    CodeRepositoryName?: string;
    GitConfig: CodeRepository.GitConfig;
    Tags?: Tag[];
  }
  export namespace CodeRepository {
    export interface Attr {
      CodeRepositoryName: string;
    }
    export interface GitConfig {
      Branch?: string;
      RepositoryUrl: string;
      SecretArn?: string;
    }
  }
  export interface DataQualityJobDefinition {
    DataQualityAppSpecification: DataQualityJobDefinition.DataQualityAppSpecification;
    DataQualityBaselineConfig?: DataQualityJobDefinition.DataQualityBaselineConfig;
    DataQualityJobInput: DataQualityJobDefinition.DataQualityJobInput;
    DataQualityJobOutputConfig: DataQualityJobDefinition.MonitoringOutputConfig;
    EndpointName?: string;
    JobDefinitionName?: string;
    JobResources: DataQualityJobDefinition.MonitoringResources;
    NetworkConfig?: DataQualityJobDefinition.NetworkConfig;
    RoleArn: string;
    StoppingCondition?: DataQualityJobDefinition.StoppingCondition;
    Tags?: Tag[];
  }
  export namespace DataQualityJobDefinition {
    export interface Attr {
      CreationTime: string;
      JobDefinitionArn: string;
    }
    export interface BatchTransformInput {
      DataCapturedDestinationS3Uri: string;
      DatasetFormat: DatasetFormat;
      LocalPath: string;
      S3DataDistributionType?: string;
      S3InputMode?: string;
    }
    export interface ClusterConfig {
      InstanceCount: number;
      InstanceType: string;
      VolumeKmsKeyId?: string;
      VolumeSizeInGB: number;
    }
    export interface ConstraintsResource {
      S3Uri?: string;
    }
    export interface Csv {
      Header?: boolean;
    }
    export interface DataQualityAppSpecification {
      ContainerArguments?: string[];
      ContainerEntrypoint?: string[];
      Environment?: Record<string, string>;
      ImageUri: string;
      PostAnalyticsProcessorSourceUri?: string;
      RecordPreprocessorSourceUri?: string;
    }
    export interface DataQualityBaselineConfig {
      BaseliningJobName?: string;
      ConstraintsResource?: ConstraintsResource;
      StatisticsResource?: StatisticsResource;
    }
    export interface DataQualityJobInput {
      BatchTransformInput?: BatchTransformInput;
      EndpointInput?: EndpointInput;
    }
    export interface DatasetFormat {
      Csv?: Csv;
      Json?: any;
      Parquet?: boolean;
    }
    export interface EndpointInput {
      EndpointName: string;
      LocalPath: string;
      S3DataDistributionType?: string;
      S3InputMode?: string;
    }
    export interface Json {
      Line?: boolean;
    }
    export interface MonitoringOutput {
      S3Output: S3Output;
    }
    export interface MonitoringOutputConfig {
      KmsKeyId?: string;
      MonitoringOutputs: MonitoringOutput[];
    }
    export interface MonitoringResources {
      ClusterConfig: ClusterConfig;
    }
    export interface NetworkConfig {
      EnableInterContainerTrafficEncryption?: boolean;
      EnableNetworkIsolation?: boolean;
      VpcConfig?: VpcConfig;
    }
    export interface S3Output {
      LocalPath: string;
      S3UploadMode?: string;
      S3Uri: string;
    }
    export interface StatisticsResource {
      S3Uri?: string;
    }
    export interface StoppingCondition {
      MaxRuntimeInSeconds: number;
    }
    export interface VpcConfig {
      SecurityGroupIds: string[];
      Subnets: string[];
    }
  }
  export interface Device {
    Device?: Device.Device;
    DeviceFleetName: string;
    Tags?: Tag[];
  }
  export namespace Device {
    export interface Attr {}
    export interface Device {
      Description?: string;
      DeviceName: string;
      IotThingName?: string;
    }
  }
  export interface DeviceFleet {
    Description?: string;
    DeviceFleetName: string;
    OutputConfig: DeviceFleet.EdgeOutputConfig;
    RoleArn: string;
    Tags?: Tag[];
  }
  export namespace DeviceFleet {
    export interface Attr {}
    export interface EdgeOutputConfig {
      KmsKeyId?: string;
      S3OutputLocation: string;
    }
  }
  export interface Domain {
    AppNetworkAccessType?: string;
    AppSecurityGroupManagement?: string;
    AuthMode: string;
    DefaultUserSettings: Domain.UserSettings;
    DomainName: string;
    DomainSettings?: Domain.DomainSettings;
    KmsKeyId?: string;
    SubnetIds: string[];
    Tags?: Tag[];
    VpcId: string;
  }
  export namespace Domain {
    export interface Attr {
      DomainArn: string;
      DomainId: string;
      HomeEfsFileSystemId: string;
      SecurityGroupIdForDomainBoundary: string;
      SingleSignOnManagedApplicationInstanceId: string;
      Url: string;
    }
    export interface CustomImage {
      AppImageConfigName: string;
      ImageName: string;
      ImageVersionNumber?: number;
    }
    export interface DomainSettings {
      RStudioServerProDomainSettings?: RStudioServerProDomainSettings;
      SecurityGroupIds?: string[];
    }
    export interface JupyterServerAppSettings {
      DefaultResourceSpec?: ResourceSpec;
    }
    export interface KernelGatewayAppSettings {
      CustomImages?: CustomImage[];
      DefaultResourceSpec?: ResourceSpec;
    }
    export interface RSessionAppSettings {
      CustomImages?: CustomImage[];
      DefaultResourceSpec?: ResourceSpec;
    }
    export interface RStudioServerProAppSettings {
      AccessStatus?: string;
      UserGroup?: string;
    }
    export interface RStudioServerProDomainSettings {
      DefaultResourceSpec?: ResourceSpec;
      DomainExecutionRoleArn: string;
      RStudioConnectUrl?: string;
      RStudioPackageManagerUrl?: string;
    }
    export interface ResourceSpec {
      InstanceType?: string;
      LifecycleConfigArn?: string;
      SageMakerImageArn?: string;
      SageMakerImageVersionArn?: string;
    }
    export interface SharingSettings {
      NotebookOutputOption?: string;
      S3KmsKeyId?: string;
      S3OutputPath?: string;
    }
    export interface UserSettings {
      ExecutionRole?: string;
      JupyterServerAppSettings?: JupyterServerAppSettings;
      KernelGatewayAppSettings?: KernelGatewayAppSettings;
      RSessionAppSettings?: RSessionAppSettings;
      RStudioServerProAppSettings?: RStudioServerProAppSettings;
      SecurityGroups?: string[];
      SharingSettings?: SharingSettings;
    }
  }
  export interface Endpoint {
    DeploymentConfig?: Endpoint.DeploymentConfig;
    EndpointConfigName: string;
    EndpointName?: string;
    ExcludeRetainedVariantProperties?: Endpoint.VariantProperty[];
    RetainAllVariantProperties?: boolean;
    RetainDeploymentConfig?: boolean;
    Tags?: Tag[];
  }
  export namespace Endpoint {
    export interface Attr {
      EndpointName: string;
    }
    export interface Alarm {
      AlarmName: string;
    }
    export interface AutoRollbackConfig {
      Alarms: Alarm[];
    }
    export interface BlueGreenUpdatePolicy {
      MaximumExecutionTimeoutInSeconds?: number;
      TerminationWaitInSeconds?: number;
      TrafficRoutingConfiguration: TrafficRoutingConfig;
    }
    export interface CapacitySize {
      Type: string;
      Value: number;
    }
    export interface DeploymentConfig {
      AutoRollbackConfiguration?: AutoRollbackConfig;
      BlueGreenUpdatePolicy: BlueGreenUpdatePolicy;
    }
    export interface TrafficRoutingConfig {
      CanarySize?: CapacitySize;
      LinearStepSize?: CapacitySize;
      Type: string;
      WaitIntervalInSeconds?: number;
    }
    export interface VariantProperty {
      VariantPropertyType?: string;
    }
  }
  export interface EndpointConfig {
    AsyncInferenceConfig?: EndpointConfig.AsyncInferenceConfig;
    DataCaptureConfig?: EndpointConfig.DataCaptureConfig;
    EndpointConfigName?: string;
    ExplainerConfig?: EndpointConfig.ExplainerConfig;
    KmsKeyId?: string;
    ProductionVariants: EndpointConfig.ProductionVariant[];
    ShadowProductionVariants?: EndpointConfig.ProductionVariant[];
    Tags?: Tag[];
  }
  export namespace EndpointConfig {
    export interface Attr {
      EndpointConfigName: string;
    }
    export interface AsyncInferenceClientConfig {
      MaxConcurrentInvocationsPerInstance?: number;
    }
    export interface AsyncInferenceConfig {
      ClientConfig?: AsyncInferenceClientConfig;
      OutputConfig: AsyncInferenceOutputConfig;
    }
    export interface AsyncInferenceNotificationConfig {
      ErrorTopic?: string;
      SuccessTopic?: string;
    }
    export interface AsyncInferenceOutputConfig {
      KmsKeyId?: string;
      NotificationConfig?: AsyncInferenceNotificationConfig;
      S3OutputPath: string;
    }
    export interface CaptureContentTypeHeader {
      CsvContentTypes?: string[];
      JsonContentTypes?: string[];
    }
    export interface CaptureOption {
      CaptureMode: string;
    }
    export interface ClarifyExplainerConfig {
      EnableExplanations?: string;
      InferenceConfig?: ClarifyInferenceConfig;
      ShapConfig: ClarifyShapConfig;
    }
    export interface ClarifyFeatureType {}
    export interface ClarifyHeader {}
    export interface ClarifyInferenceConfig {
      ContentTemplate?: string;
      FeatureHeaders?: ClarifyHeader[];
      FeatureTypes?: ClarifyFeatureType[];
      FeaturesAttribute?: string;
      LabelAttribute?: string;
      LabelHeaders?: ClarifyHeader[];
      LabelIndex?: number;
      MaxPayloadInMB?: number;
      MaxRecordCount?: number;
      ProbabilityAttribute?: string;
      ProbabilityIndex?: number;
    }
    export interface ClarifyShapBaselineConfig {
      MimeType?: string;
      ShapBaseline?: string;
      ShapBaselineUri?: string;
    }
    export interface ClarifyShapConfig {
      NumberOfSamples?: number;
      Seed?: number;
      ShapBaselineConfig: ClarifyShapBaselineConfig;
      TextConfig?: ClarifyTextConfig;
      UseLogit?: boolean;
    }
    export interface ClarifyTextConfig {
      Granularity: string;
      Language: string;
    }
    export interface DataCaptureConfig {
      CaptureContentTypeHeader?: CaptureContentTypeHeader;
      CaptureOptions: CaptureOption[];
      DestinationS3Uri: string;
      EnableCapture?: boolean;
      InitialSamplingPercentage: number;
      KmsKeyId?: string;
    }
    export interface ExplainerConfig {
      ClarifyExplainerConfig?: ClarifyExplainerConfig;
    }
    export interface ProductionVariant {
      AcceleratorType?: string;
      ContainerStartupHealthCheckTimeoutInSeconds?: number;
      InitialInstanceCount?: number;
      InitialVariantWeight: number;
      InstanceType?: string;
      ModelDataDownloadTimeoutInSeconds?: number;
      ModelName: string;
      ServerlessConfig?: ServerlessConfig;
      VariantName: string;
      VolumeSizeInGB?: number;
    }
    export interface ServerlessConfig {
      MaxConcurrency: number;
      MemorySizeInMB: number;
    }
  }
  export interface FeatureGroup {
    Description?: string;
    EventTimeFeatureName: string;
    FeatureDefinitions: FeatureGroup.FeatureDefinition[];
    FeatureGroupName: string;
    OfflineStoreConfig?: any;
    OnlineStoreConfig?: any;
    RecordIdentifierFeatureName: string;
    RoleArn?: string;
    Tags?: Tag[];
  }
  export namespace FeatureGroup {
    export interface Attr {}
    export interface DataCatalogConfig {
      Catalog: string;
      Database: string;
      TableName: string;
    }
    export interface FeatureDefinition {
      FeatureName: string;
      FeatureType: string;
    }
    export interface OfflineStoreConfig {
      DataCatalogConfig?: DataCatalogConfig;
      DisableGlueTableCreation?: boolean;
      S3StorageConfig: S3StorageConfig;
      TableFormat?: string;
    }
    export interface OnlineStoreConfig {
      EnableOnlineStore?: boolean;
      SecurityConfig?: OnlineStoreSecurityConfig;
    }
    export interface OnlineStoreSecurityConfig {
      KmsKeyId?: string;
    }
    export interface S3StorageConfig {
      KmsKeyId?: string;
      S3Uri: string;
    }
  }
  export interface Image {
    ImageDescription?: string;
    ImageDisplayName?: string;
    ImageName: string;
    ImageRoleArn: string;
    Tags?: Tag[];
  }
  export interface ImageVersion {
    BaseImage: string;
    ImageName: string;
  }
  export interface Model {
    Containers?: Model.ContainerDefinition[];
    EnableNetworkIsolation?: boolean;
    ExecutionRoleArn: string;
    InferenceExecutionConfig?: Model.InferenceExecutionConfig;
    ModelName?: string;
    PrimaryContainer?: Model.ContainerDefinition;
    Tags?: Tag[];
    VpcConfig?: Model.VpcConfig;
  }
  export namespace Model {
    export interface Attr {
      ModelName: string;
    }
    export interface ContainerDefinition {
      ContainerHostname?: string;
      Environment?: any;
      Image?: string;
      ImageConfig?: ImageConfig;
      InferenceSpecificationName?: string;
      Mode?: string;
      ModelDataUrl?: string;
      ModelPackageName?: string;
      MultiModelConfig?: MultiModelConfig;
    }
    export interface ImageConfig {
      RepositoryAccessMode: string;
      RepositoryAuthConfig?: RepositoryAuthConfig;
    }
    export interface InferenceExecutionConfig {
      Mode: string;
    }
    export interface MultiModelConfig {
      ModelCacheSetting?: string;
    }
    export interface RepositoryAuthConfig {
      RepositoryCredentialsProviderArn: string;
    }
    export interface VpcConfig {
      SecurityGroupIds: string[];
      Subnets: string[];
    }
  }
  export interface ModelBiasJobDefinition {
    EndpointName?: string;
    JobDefinitionName?: string;
    JobResources: ModelBiasJobDefinition.MonitoringResources;
    ModelBiasAppSpecification: ModelBiasJobDefinition.ModelBiasAppSpecification;
    ModelBiasBaselineConfig?: ModelBiasJobDefinition.ModelBiasBaselineConfig;
    ModelBiasJobInput: ModelBiasJobDefinition.ModelBiasJobInput;
    ModelBiasJobOutputConfig: ModelBiasJobDefinition.MonitoringOutputConfig;
    NetworkConfig?: ModelBiasJobDefinition.NetworkConfig;
    RoleArn: string;
    StoppingCondition?: ModelBiasJobDefinition.StoppingCondition;
    Tags?: Tag[];
  }
  export namespace ModelBiasJobDefinition {
    export interface Attr {
      CreationTime: string;
      JobDefinitionArn: string;
    }
    export interface BatchTransformInput {
      DataCapturedDestinationS3Uri: string;
      DatasetFormat: DatasetFormat;
      EndTimeOffset?: string;
      FeaturesAttribute?: string;
      InferenceAttribute?: string;
      LocalPath: string;
      ProbabilityAttribute?: string;
      ProbabilityThresholdAttribute?: number;
      S3DataDistributionType?: string;
      S3InputMode?: string;
      StartTimeOffset?: string;
    }
    export interface ClusterConfig {
      InstanceCount: number;
      InstanceType: string;
      VolumeKmsKeyId?: string;
      VolumeSizeInGB: number;
    }
    export interface ConstraintsResource {
      S3Uri?: string;
    }
    export interface Csv {
      Header?: boolean;
    }
    export interface DatasetFormat {
      Csv?: Csv;
      Json?: any;
      Parquet?: boolean;
    }
    export interface EndpointInput {
      EndTimeOffset?: string;
      EndpointName: string;
      FeaturesAttribute?: string;
      InferenceAttribute?: string;
      LocalPath: string;
      ProbabilityAttribute?: string;
      ProbabilityThresholdAttribute?: number;
      S3DataDistributionType?: string;
      S3InputMode?: string;
      StartTimeOffset?: string;
    }
    export interface Json {
      Line?: boolean;
    }
    export interface ModelBiasAppSpecification {
      ConfigUri: string;
      Environment?: Record<string, string>;
      ImageUri: string;
    }
    export interface ModelBiasBaselineConfig {
      BaseliningJobName?: string;
      ConstraintsResource?: ConstraintsResource;
    }
    export interface ModelBiasJobInput {
      BatchTransformInput?: BatchTransformInput;
      EndpointInput?: EndpointInput;
      GroundTruthS3Input: MonitoringGroundTruthS3Input;
    }
    export interface MonitoringGroundTruthS3Input {
      S3Uri: string;
    }
    export interface MonitoringOutput {
      S3Output: S3Output;
    }
    export interface MonitoringOutputConfig {
      KmsKeyId?: string;
      MonitoringOutputs: MonitoringOutput[];
    }
    export interface MonitoringResources {
      ClusterConfig: ClusterConfig;
    }
    export interface NetworkConfig {
      EnableInterContainerTrafficEncryption?: boolean;
      EnableNetworkIsolation?: boolean;
      VpcConfig?: VpcConfig;
    }
    export interface S3Output {
      LocalPath: string;
      S3UploadMode?: string;
      S3Uri: string;
    }
    export interface StoppingCondition {
      MaxRuntimeInSeconds: number;
    }
    export interface VpcConfig {
      SecurityGroupIds: string[];
      Subnets: string[];
    }
  }
  export interface ModelExplainabilityJobDefinition {
    EndpointName?: string;
    JobDefinitionName?: string;
    JobResources: ModelExplainabilityJobDefinition.MonitoringResources;
    ModelExplainabilityAppSpecification: ModelExplainabilityJobDefinition.ModelExplainabilityAppSpecification;
    ModelExplainabilityBaselineConfig?: ModelExplainabilityJobDefinition.ModelExplainabilityBaselineConfig;
    ModelExplainabilityJobInput: ModelExplainabilityJobDefinition.ModelExplainabilityJobInput;
    ModelExplainabilityJobOutputConfig: ModelExplainabilityJobDefinition.MonitoringOutputConfig;
    NetworkConfig?: ModelExplainabilityJobDefinition.NetworkConfig;
    RoleArn: string;
    StoppingCondition?: ModelExplainabilityJobDefinition.StoppingCondition;
    Tags?: Tag[];
  }
  export namespace ModelExplainabilityJobDefinition {
    export interface Attr {
      CreationTime: string;
      JobDefinitionArn: string;
    }
    export interface BatchTransformInput {
      DataCapturedDestinationS3Uri: string;
      DatasetFormat: DatasetFormat;
      FeaturesAttribute?: string;
      InferenceAttribute?: string;
      LocalPath: string;
      ProbabilityAttribute?: string;
      S3DataDistributionType?: string;
      S3InputMode?: string;
    }
    export interface ClusterConfig {
      InstanceCount: number;
      InstanceType: string;
      VolumeKmsKeyId?: string;
      VolumeSizeInGB: number;
    }
    export interface ConstraintsResource {
      S3Uri?: string;
    }
    export interface Csv {
      Header?: boolean;
    }
    export interface DatasetFormat {
      Csv?: Csv;
      Json?: any;
      Parquet?: boolean;
    }
    export interface EndpointInput {
      EndpointName: string;
      FeaturesAttribute?: string;
      InferenceAttribute?: string;
      LocalPath: string;
      ProbabilityAttribute?: string;
      S3DataDistributionType?: string;
      S3InputMode?: string;
    }
    export interface Json {
      Line?: boolean;
    }
    export interface ModelExplainabilityAppSpecification {
      ConfigUri: string;
      Environment?: Record<string, string>;
      ImageUri: string;
    }
    export interface ModelExplainabilityBaselineConfig {
      BaseliningJobName?: string;
      ConstraintsResource?: ConstraintsResource;
    }
    export interface ModelExplainabilityJobInput {
      BatchTransformInput?: BatchTransformInput;
      EndpointInput?: EndpointInput;
    }
    export interface MonitoringOutput {
      S3Output: S3Output;
    }
    export interface MonitoringOutputConfig {
      KmsKeyId?: string;
      MonitoringOutputs: MonitoringOutput[];
    }
    export interface MonitoringResources {
      ClusterConfig: ClusterConfig;
    }
    export interface NetworkConfig {
      EnableInterContainerTrafficEncryption?: boolean;
      EnableNetworkIsolation?: boolean;
      VpcConfig?: VpcConfig;
    }
    export interface S3Output {
      LocalPath: string;
      S3UploadMode?: string;
      S3Uri: string;
    }
    export interface StoppingCondition {
      MaxRuntimeInSeconds: number;
    }
    export interface VpcConfig {
      SecurityGroupIds: string[];
      Subnets: string[];
    }
  }
  export interface ModelPackage {
    AdditionalInferenceSpecificationDefinition?: ModelPackage.AdditionalInferenceSpecificationDefinition;
    AdditionalInferenceSpecifications?: ModelPackage.AdditionalInferenceSpecificationDefinition[];
    AdditionalInferenceSpecificationsToAdd?: ModelPackage.AdditionalInferenceSpecificationDefinition[];
    ApprovalDescription?: string;
    CertifyForMarketplace?: boolean;
    ClientToken?: string;
    CreatedBy?: ModelPackage.UserContext;
    CustomerMetadataProperties?: Record<string, string>;
    Domain?: string;
    DriftCheckBaselines?: ModelPackage.DriftCheckBaselines;
    Environment?: Record<string, string>;
    InferenceSpecification?: ModelPackage.InferenceSpecification;
    LastModifiedBy?: ModelPackage.UserContext;
    LastModifiedTime?: string;
    MetadataProperties?: ModelPackage.MetadataProperties;
    ModelApprovalStatus?: string;
    ModelMetrics?: ModelPackage.ModelMetrics;
    ModelPackageDescription?: string;
    ModelPackageGroupName?: string;
    ModelPackageName?: string;
    ModelPackageStatusDetails?: ModelPackage.ModelPackageStatusDetails;
    ModelPackageStatusItem?: ModelPackage.ModelPackageStatusItem;
    ModelPackageVersion?: number;
    SamplePayloadUrl?: string;
    SourceAlgorithmSpecification?: ModelPackage.SourceAlgorithmSpecification;
    Tags?: Tag[];
    Task?: string;
    ValidationSpecification?: ModelPackage.ValidationSpecification;
  }
  export namespace ModelPackage {
    export interface Attr {
      CreationTime: string;
      ModelPackageArn: string;
      ModelPackageStatus: string;
    }
    export interface AdditionalInferenceSpecificationDefinition {
      Containers: ModelPackageContainerDefinition[];
      Description?: string;
      Name: string;
      SupportedContentTypes?: string[];
      SupportedRealtimeInferenceInstanceTypes?: string[];
      SupportedResponseMIMETypes?: string[];
      SupportedTransformInstanceTypes?: string[];
    }
    export interface Bias {
      PostTrainingReport?: MetricsSource;
      PreTrainingReport?: MetricsSource;
      Report?: MetricsSource;
    }
    export interface DataSource {
      S3DataSource: S3DataSource;
    }
    export interface DriftCheckBaselines {
      Bias?: DriftCheckBias;
      Explainability?: DriftCheckExplainability;
      ModelDataQuality?: DriftCheckModelDataQuality;
      ModelQuality?: DriftCheckModelQuality;
    }
    export interface DriftCheckBias {
      ConfigFile?: FileSource;
      PostTrainingConstraints?: MetricsSource;
      PreTrainingConstraints?: MetricsSource;
    }
    export interface DriftCheckExplainability {
      ConfigFile?: FileSource;
      Constraints?: MetricsSource;
    }
    export interface DriftCheckModelDataQuality {
      Constraints?: MetricsSource;
      Statistics?: MetricsSource;
    }
    export interface DriftCheckModelQuality {
      Constraints?: MetricsSource;
      Statistics?: MetricsSource;
    }
    export interface Explainability {
      Report?: MetricsSource;
    }
    export interface FileSource {
      ContentDigest?: string;
      ContentType?: string;
      S3Uri: string;
    }
    export interface InferenceSpecification {
      Containers: ModelPackageContainerDefinition[];
      SupportedContentTypes: string[];
      SupportedRealtimeInferenceInstanceTypes?: string[];
      SupportedResponseMIMETypes: string[];
      SupportedTransformInstanceTypes?: string[];
    }
    export interface MetadataProperties {
      CommitId?: string;
      GeneratedBy?: string;
      ProjectId?: string;
      Repository?: string;
    }
    export interface MetricsSource {
      ContentDigest?: string;
      ContentType: string;
      S3Uri: string;
    }
    export interface ModelDataQuality {
      Constraints?: MetricsSource;
      Statistics?: MetricsSource;
    }
    export interface ModelInput {
      DataInputConfig: string;
    }
    export interface ModelMetrics {
      Bias?: Bias;
      Explainability?: Explainability;
      ModelDataQuality?: ModelDataQuality;
      ModelQuality?: ModelQuality;
    }
    export interface ModelPackageContainerDefinition {
      ContainerHostname?: string;
      Environment?: Record<string, string>;
      Framework?: string;
      FrameworkVersion?: string;
      Image: string;
      ImageDigest?: string;
      ModelDataUrl?: string;
      ModelInput?: any;
      NearestModelName?: string;
      ProductId?: string;
    }
    export interface ModelPackageStatusDetails {
      ImageScanStatuses?: ModelPackageStatusItem[];
      ValidationStatuses: ModelPackageStatusItem[];
    }
    export interface ModelPackageStatusItem {
      FailureReason?: string;
      Name: string;
      Status: string;
    }
    export interface ModelQuality {
      Constraints?: MetricsSource;
      Statistics?: MetricsSource;
    }
    export interface S3DataSource {
      S3DataType: string;
      S3Uri: string;
    }
    export interface SourceAlgorithm {
      AlgorithmName: string;
      ModelDataUrl?: string;
    }
    export interface SourceAlgorithmSpecification {
      SourceAlgorithms: SourceAlgorithm[];
    }
    export interface TransformInput {
      CompressionType?: string;
      ContentType?: string;
      DataSource: DataSource;
      SplitType?: string;
    }
    export interface TransformJobDefinition {
      BatchStrategy?: string;
      Environment?: Record<string, string>;
      MaxConcurrentTransforms?: number;
      MaxPayloadInMB?: number;
      TransformInput: TransformInput;
      TransformOutput: TransformOutput;
      TransformResources: TransformResources;
    }
    export interface TransformOutput {
      Accept?: string;
      AssembleWith?: string;
      KmsKeyId?: string;
      S3OutputPath: string;
    }
    export interface TransformResources {
      InstanceCount: number;
      InstanceType: string;
      VolumeKmsKeyId?: string;
    }
    export interface UserContext {
      DomainId?: string;
      UserProfileArn?: string;
      UserProfileName?: string;
    }
    export interface ValidationProfile {
      ProfileName: string;
      TransformJobDefinition: TransformJobDefinition;
    }
    export interface ValidationSpecification {
      ValidationProfiles: ValidationProfile[];
      ValidationRole: string;
    }
  }
  export interface ModelPackageGroup {
    ModelPackageGroupDescription?: string;
    ModelPackageGroupName: string;
    ModelPackageGroupPolicy?: any;
    Tags?: Tag[];
  }
  export interface ModelQualityJobDefinition {
    EndpointName?: string;
    JobDefinitionName?: string;
    JobResources: ModelQualityJobDefinition.MonitoringResources;
    ModelQualityAppSpecification: ModelQualityJobDefinition.ModelQualityAppSpecification;
    ModelQualityBaselineConfig?: ModelQualityJobDefinition.ModelQualityBaselineConfig;
    ModelQualityJobInput: ModelQualityJobDefinition.ModelQualityJobInput;
    ModelQualityJobOutputConfig: ModelQualityJobDefinition.MonitoringOutputConfig;
    NetworkConfig?: ModelQualityJobDefinition.NetworkConfig;
    RoleArn: string;
    StoppingCondition?: ModelQualityJobDefinition.StoppingCondition;
    Tags?: Tag[];
  }
  export namespace ModelQualityJobDefinition {
    export interface Attr {
      CreationTime: string;
      JobDefinitionArn: string;
    }
    export interface BatchTransformInput {
      DataCapturedDestinationS3Uri: string;
      DatasetFormat: DatasetFormat;
      EndTimeOffset?: string;
      InferenceAttribute?: string;
      LocalPath: string;
      ProbabilityAttribute?: string;
      ProbabilityThresholdAttribute?: number;
      S3DataDistributionType?: string;
      S3InputMode?: string;
      StartTimeOffset?: string;
    }
    export interface ClusterConfig {
      InstanceCount: number;
      InstanceType: string;
      VolumeKmsKeyId?: string;
      VolumeSizeInGB: number;
    }
    export interface ConstraintsResource {
      S3Uri?: string;
    }
    export interface Csv {
      Header?: boolean;
    }
    export interface DatasetFormat {
      Csv?: Csv;
      Json?: any;
      Parquet?: boolean;
    }
    export interface EndpointInput {
      EndTimeOffset?: string;
      EndpointName: string;
      InferenceAttribute?: string;
      LocalPath: string;
      ProbabilityAttribute?: string;
      ProbabilityThresholdAttribute?: number;
      S3DataDistributionType?: string;
      S3InputMode?: string;
      StartTimeOffset?: string;
    }
    export interface Json {
      Line?: boolean;
    }
    export interface ModelQualityAppSpecification {
      ContainerArguments?: string[];
      ContainerEntrypoint?: string[];
      Environment?: Record<string, string>;
      ImageUri: string;
      PostAnalyticsProcessorSourceUri?: string;
      ProblemType: string;
      RecordPreprocessorSourceUri?: string;
    }
    export interface ModelQualityBaselineConfig {
      BaseliningJobName?: string;
      ConstraintsResource?: ConstraintsResource;
    }
    export interface ModelQualityJobInput {
      BatchTransformInput?: BatchTransformInput;
      EndpointInput?: EndpointInput;
      GroundTruthS3Input: MonitoringGroundTruthS3Input;
    }
    export interface MonitoringGroundTruthS3Input {
      S3Uri: string;
    }
    export interface MonitoringOutput {
      S3Output: S3Output;
    }
    export interface MonitoringOutputConfig {
      KmsKeyId?: string;
      MonitoringOutputs: MonitoringOutput[];
    }
    export interface MonitoringResources {
      ClusterConfig: ClusterConfig;
    }
    export interface NetworkConfig {
      EnableInterContainerTrafficEncryption?: boolean;
      EnableNetworkIsolation?: boolean;
      VpcConfig?: VpcConfig;
    }
    export interface S3Output {
      LocalPath: string;
      S3UploadMode?: string;
      S3Uri: string;
    }
    export interface StoppingCondition {
      MaxRuntimeInSeconds: number;
    }
    export interface VpcConfig {
      SecurityGroupIds: string[];
      Subnets: string[];
    }
  }
  export interface MonitoringSchedule {
    EndpointName?: string;
    FailureReason?: string;
    LastMonitoringExecutionSummary?: MonitoringSchedule.MonitoringExecutionSummary;
    MonitoringScheduleConfig: MonitoringSchedule.MonitoringScheduleConfig;
    MonitoringScheduleName: string;
    MonitoringScheduleStatus?: string;
    Tags?: Tag[];
  }
  export namespace MonitoringSchedule {
    export interface Attr {
      CreationTime: string;
      LastModifiedTime: string;
      MonitoringScheduleArn: string;
    }
    export interface BaselineConfig {
      ConstraintsResource?: ConstraintsResource;
      StatisticsResource?: StatisticsResource;
    }
    export interface BatchTransformInput {
      DataCapturedDestinationS3Uri: string;
      DatasetFormat: DatasetFormat;
      LocalPath: string;
      S3DataDistributionType?: string;
      S3InputMode?: string;
    }
    export interface ClusterConfig {
      InstanceCount: number;
      InstanceType: string;
      VolumeKmsKeyId?: string;
      VolumeSizeInGB: number;
    }
    export interface ConstraintsResource {
      S3Uri?: string;
    }
    export interface Csv {
      Header?: boolean;
    }
    export interface DatasetFormat {
      Csv?: Csv;
      Json?: any;
      Parquet?: boolean;
    }
    export interface EndpointInput {
      EndpointName: string;
      LocalPath: string;
      S3DataDistributionType?: string;
      S3InputMode?: string;
    }
    export interface Json {
      Line?: boolean;
    }
    export interface MonitoringAppSpecification {
      ContainerArguments?: string[];
      ContainerEntrypoint?: string[];
      ImageUri: string;
      PostAnalyticsProcessorSourceUri?: string;
      RecordPreprocessorSourceUri?: string;
    }
    export interface MonitoringExecutionSummary {
      CreationTime: string;
      EndpointName?: string;
      FailureReason?: string;
      LastModifiedTime: string;
      MonitoringExecutionStatus: string;
      MonitoringScheduleName: string;
      ProcessingJobArn?: string;
      ScheduledTime: string;
    }
    export interface MonitoringInput {
      BatchTransformInput?: BatchTransformInput;
      EndpointInput?: EndpointInput;
    }
    export interface MonitoringJobDefinition {
      BaselineConfig?: BaselineConfig;
      Environment?: Record<string, string>;
      MonitoringAppSpecification: MonitoringAppSpecification;
      MonitoringInputs: MonitoringInput[];
      MonitoringOutputConfig: MonitoringOutputConfig;
      MonitoringResources: MonitoringResources;
      NetworkConfig?: NetworkConfig;
      RoleArn: string;
      StoppingCondition?: StoppingCondition;
    }
    export interface MonitoringOutput {
      S3Output: S3Output;
    }
    export interface MonitoringOutputConfig {
      KmsKeyId?: string;
      MonitoringOutputs: MonitoringOutput[];
    }
    export interface MonitoringResources {
      ClusterConfig: ClusterConfig;
    }
    export interface MonitoringScheduleConfig {
      MonitoringJobDefinition?: MonitoringJobDefinition;
      MonitoringJobDefinitionName?: string;
      MonitoringType?: string;
      ScheduleConfig?: ScheduleConfig;
    }
    export interface NetworkConfig {
      EnableInterContainerTrafficEncryption?: boolean;
      EnableNetworkIsolation?: boolean;
      VpcConfig?: VpcConfig;
    }
    export interface S3Output {
      LocalPath: string;
      S3UploadMode?: string;
      S3Uri: string;
    }
    export interface ScheduleConfig {
      ScheduleExpression: string;
    }
    export interface StatisticsResource {
      S3Uri?: string;
    }
    export interface StoppingCondition {
      MaxRuntimeInSeconds: number;
    }
    export interface VpcConfig {
      SecurityGroupIds: string[];
      Subnets: string[];
    }
  }
  export interface NotebookInstance {
    AcceleratorTypes?: string[];
    AdditionalCodeRepositories?: string[];
    DefaultCodeRepository?: string;
    DirectInternetAccess?: string;
    InstanceMetadataServiceConfiguration?: NotebookInstance.InstanceMetadataServiceConfiguration;
    InstanceType: string;
    KmsKeyId?: string;
    LifecycleConfigName?: string;
    NotebookInstanceName?: string;
    PlatformIdentifier?: string;
    RoleArn: string;
    RootAccess?: string;
    SecurityGroupIds?: string[];
    SubnetId?: string;
    Tags?: Tag[];
    VolumeSizeInGB?: number;
  }
  export namespace NotebookInstance {
    export interface Attr {
      NotebookInstanceName: string;
    }
    export interface InstanceMetadataServiceConfiguration {
      MinimumInstanceMetadataServiceVersion: string;
    }
  }
  export interface NotebookInstanceLifecycleConfig {
    NotebookInstanceLifecycleConfigName?: string;
    OnCreate?: NotebookInstanceLifecycleConfig.NotebookInstanceLifecycleHook[];
    OnStart?: NotebookInstanceLifecycleConfig.NotebookInstanceLifecycleHook[];
  }
  export namespace NotebookInstanceLifecycleConfig {
    export interface Attr {
      NotebookInstanceLifecycleConfigName: string;
    }
    export interface NotebookInstanceLifecycleHook {
      Content?: string;
    }
  }
  export interface Pipeline {
    ParallelismConfiguration?: any;
    PipelineDefinition: any;
    PipelineDescription?: string;
    PipelineDisplayName?: string;
    PipelineName: string;
    RoleArn: string;
    Tags?: Tag[];
  }
  export namespace Pipeline {
    export interface Attr {}
    export interface ParallelismConfiguration {
      MaxParallelExecutionSteps: number;
    }
    export interface PipelineDefinition {
      PipelineDefinitionBody?: string;
      PipelineDefinitionS3Location?: S3Location;
    }
    export interface S3Location {
      Bucket: string;
      ETag?: string;
      Key: string;
      Version?: string;
    }
  }
  export interface Project {
    ProjectDescription?: string;
    ProjectName: string;
    ServiceCatalogProvisioningDetails: any;
    Tags?: Tag[];
  }
  export namespace Project {
    export interface Attr {
      CreationTime: string;
      ProjectArn: string;
      ProjectId: string;
      ProjectStatus: string;
      "ServiceCatalogProvisionedProductDetails.ProvisionedProductId": string;
      "ServiceCatalogProvisionedProductDetails.ProvisionedProductStatusMessage": string;
    }
    export interface ProvisioningParameter {
      Key: string;
      Value: string;
    }
    export interface ServiceCatalogProvisionedProductDetails {
      ProvisionedProductId?: string;
      ProvisionedProductStatusMessage?: string;
    }
    export interface ServiceCatalogProvisioningDetails {
      PathId?: string;
      ProductId: string;
      ProvisioningArtifactId?: string;
      ProvisioningParameters?: ProvisioningParameter[];
    }
  }
  export interface UserProfile {
    DomainId: string;
    SingleSignOnUserIdentifier?: string;
    SingleSignOnUserValue?: string;
    Tags?: Tag[];
    UserProfileName: string;
    UserSettings?: UserProfile.UserSettings;
  }
  export namespace UserProfile {
    export interface Attr {
      UserProfileArn: string;
    }
    export interface CustomImage {
      AppImageConfigName: string;
      ImageName: string;
      ImageVersionNumber?: number;
    }
    export interface JupyterServerAppSettings {
      DefaultResourceSpec?: ResourceSpec;
    }
    export interface KernelGatewayAppSettings {
      CustomImages?: CustomImage[];
      DefaultResourceSpec?: ResourceSpec;
    }
    export interface RStudioServerProAppSettings {
      AccessStatus?: string;
      UserGroup?: string;
    }
    export interface ResourceSpec {
      InstanceType?: string;
      SageMakerImageArn?: string;
      SageMakerImageVersionArn?: string;
    }
    export interface SharingSettings {
      NotebookOutputOption?: string;
      S3KmsKeyId?: string;
      S3OutputPath?: string;
    }
    export interface UserSettings {
      ExecutionRole?: string;
      JupyterServerAppSettings?: JupyterServerAppSettings;
      KernelGatewayAppSettings?: KernelGatewayAppSettings;
      RStudioServerProAppSettings?: RStudioServerProAppSettings;
      SecurityGroups?: string[];
      SharingSettings?: SharingSettings;
    }
  }
  export interface Workteam {
    Description?: string;
    MemberDefinitions?: Workteam.MemberDefinition[];
    NotificationConfiguration?: Workteam.NotificationConfiguration;
    Tags?: Tag[];
    WorkforceName?: string;
    WorkteamName?: string;
  }
  export namespace Workteam {
    export interface Attr {
      WorkteamName: string;
    }
    export interface CognitoMemberDefinition {
      CognitoClientId: string;
      CognitoUserGroup: string;
      CognitoUserPool: string;
    }
    export interface MemberDefinition {
      CognitoMemberDefinition?: CognitoMemberDefinition;
      OidcMemberDefinition?: OidcMemberDefinition;
    }
    export interface NotificationConfiguration {
      NotificationTopicArn: string;
    }
    export interface OidcMemberDefinition {
      OidcGroups: string[];
    }
  }
}
export namespace Scheduler {
  export interface Schedule {
    Description?: string;
    EndDate?: string;
    FlexibleTimeWindow: Schedule.FlexibleTimeWindow;
    GroupName?: string;
    KmsKeyArn?: string;
    Name?: string;
    ScheduleExpression: string;
    ScheduleExpressionTimezone?: string;
    StartDate?: string;
    State?: string;
    Target: Schedule.Target;
  }
  export namespace Schedule {
    export interface Attr {
      Arn: string;
    }
    export interface AwsVpcConfiguration {
      AssignPublicIp?: string;
      SecurityGroups?: string[];
      Subnets: string[];
    }
    export interface CapacityProviderStrategyItem {
      Base?: number;
      CapacityProvider: string;
      Weight?: number;
    }
    export interface DeadLetterConfig {
      Arn?: string;
    }
    export interface EcsParameters {
      CapacityProviderStrategy?: CapacityProviderStrategyItem[];
      EnableECSManagedTags?: boolean;
      EnableExecuteCommand?: boolean;
      Group?: string;
      LaunchType?: string;
      NetworkConfiguration?: NetworkConfiguration;
      PlacementConstraints?: PlacementConstraint[];
      PlacementStrategy?: PlacementStrategy[];
      PlatformVersion?: string;
      PropagateTags?: string;
      ReferenceId?: string;
      Tags?: any;
      TaskCount?: number;
      TaskDefinitionArn: string;
    }
    export interface EventBridgeParameters {
      DetailType: string;
      Source: string;
    }
    export interface FlexibleTimeWindow {
      MaximumWindowInMinutes?: number;
      Mode: string;
    }
    export interface KinesisParameters {
      PartitionKey: string;
    }
    export interface NetworkConfiguration {
      AwsvpcConfiguration?: AwsVpcConfiguration;
    }
    export interface PlacementConstraint {
      Expression?: string;
      Type?: string;
    }
    export interface PlacementStrategy {
      Field?: string;
      Type?: string;
    }
    export interface RetryPolicy {
      MaximumEventAgeInSeconds?: number;
      MaximumRetryAttempts?: number;
    }
    export interface SageMakerPipelineParameter {
      Name: string;
      Value: string;
    }
    export interface SageMakerPipelineParameters {
      PipelineParameterList?: SageMakerPipelineParameter[];
    }
    export interface SqsParameters {
      MessageGroupId?: string;
    }
    export interface Target {
      Arn: string;
      DeadLetterConfig?: DeadLetterConfig;
      EcsParameters?: EcsParameters;
      EventBridgeParameters?: EventBridgeParameters;
      Input?: string;
      KinesisParameters?: KinesisParameters;
      RetryPolicy?: RetryPolicy;
      RoleArn: string;
      SageMakerPipelineParameters?: SageMakerPipelineParameters;
      SqsParameters?: SqsParameters;
    }
  }
  export interface ScheduleGroup {
    Name?: string;
    Tags?: Tag[];
  }
}
export namespace SecretsManager {
  export interface ResourcePolicy {
    BlockPublicPolicy?: boolean;
    ResourcePolicy: any;
    SecretId: string;
  }
  export interface RotationSchedule {
    HostedRotationLambda?: RotationSchedule.HostedRotationLambda;
    RotateImmediatelyOnUpdate?: boolean;
    RotationLambdaARN?: string;
    RotationRules?: RotationSchedule.RotationRules;
    SecretId: string;
  }
  export namespace RotationSchedule {
    export interface Attr {}
    export interface HostedRotationLambda {
      ExcludeCharacters?: string;
      KmsKeyArn?: string;
      MasterSecretArn?: string;
      MasterSecretKmsKeyArn?: string;
      RotationLambdaName?: string;
      RotationType: string;
      SuperuserSecretArn?: string;
      SuperuserSecretKmsKeyArn?: string;
      VpcSecurityGroupIds?: string;
      VpcSubnetIds?: string;
    }
    export interface RotationRules {
      AutomaticallyAfterDays?: number;
      Duration?: string;
      ScheduleExpression?: string;
    }
  }
  export interface Secret {
    Description?: string;
    GenerateSecretString?: Secret.GenerateSecretString;
    KmsKeyId?: string;
    Name?: string;
    ReplicaRegions?: Secret.ReplicaRegion[];
    SecretString?: string;
    Tags?: Tag[];
  }
  export namespace Secret {
    export interface Attr {
      Id: string;
    }
    export interface GenerateSecretString {
      ExcludeCharacters?: string;
      ExcludeLowercase?: boolean;
      ExcludeNumbers?: boolean;
      ExcludePunctuation?: boolean;
      ExcludeUppercase?: boolean;
      GenerateStringKey?: string;
      IncludeSpace?: boolean;
      PasswordLength?: number;
      RequireEachIncludedType?: boolean;
      SecretStringTemplate?: string;
    }
    export interface ReplicaRegion {
      KmsKeyId?: string;
      Region: string;
    }
  }
  export interface SecretTargetAttachment {
    SecretId: string;
    TargetId: string;
    TargetType: string;
  }
}
export namespace SecurityHub {
  export interface Hub {
    Tags?: any;
  }
}
export namespace Serverless {
  export interface Api {
    AccessLogSetting?: Api.AccessLogSetting;
    Auth?: Api.Auth;
    BinaryMediaTypes?: string[];
    CacheClusterEnabled?: boolean;
    CacheClusterSize?: string;
    CanarySetting?: Api.CanarySetting;
    Cors?: never;
    DefinitionBody?: any;
    DefinitionUri?: never;
    Description?: string;
    DisableExecuteApiEndpoint?: boolean;
    Domain?: Api.DomainConfiguration;
    EndpointConfiguration?: never;
    GatewayResponses?: any;
    MethodSettings?: any[];
    MinimumCompressionSize?: number;
    Models?: any;
    Name?: string;
    OpenApiVersion?: string;
    StageName: string;
    Tags?: Record<string, string>;
    TracingEnabled?: boolean;
    Variables?: Record<string, string>;
  }
  export namespace Api {
    export interface Attr {}
    export interface AccessLogSetting {
      DestinationArn?: string;
      Format?: string;
    }
    export interface Auth {
      AddDefaultAuthorizerToCorsPreflight?: boolean;
      Authorizers?: any;
      DefaultAuthorizer?: string;
    }
    export interface CanarySetting {
      DeploymentId?: string;
      PercentTraffic?: number;
      StageVariableOverrides?: Record<string, string>;
      UseStageCache?: boolean;
    }
    export interface CorsConfiguration {
      AllowCredentials?: boolean;
      AllowHeaders?: string;
      AllowMethods?: string;
      AllowOrigin: string;
      MaxAge?: string;
    }
    export interface DomainConfiguration {
      BasePath?: string[];
      CertificateArn: string;
      DomainName: string;
      EndpointConfiguration?: string;
      MutualTlsAuthentication?: MutualTlsAuthentication;
      OwnershipVerificationCertificateArn?: string;
      Route53?: Route53Configuration;
      SecurityPolicy?: string;
    }
    export interface EndpointConfiguration {
      Type?: string;
      VpcEndpointIds?: string[];
    }
    export interface MutualTlsAuthentication {
      TruststoreUri?: string;
      TruststoreVersion?: string;
    }
    export interface Route53Configuration {
      DistributedDomainName?: string;
      EvaluateTargetHealth?: boolean;
      HostedZoneId?: string;
      HostedZoneName?: string;
      IpV6?: boolean;
    }
    export interface S3Location {
      Bucket: string;
      Key: string;
      Version: number;
    }
  }
  export interface Application {
    Location: never;
    NotificationArns?: string[];
    Parameters?: Record<string, string>;
    Tags?: Record<string, string>;
    TimeoutInMinutes?: number;
  }
  export namespace Application {
    export interface Attr {}
    export interface ApplicationLocation {
      ApplicationId: string;
      SemanticVersion: string;
    }
  }
  export interface Function {
    Architectures?: string[];
    AssumeRolePolicyDocument?: any;
    AutoPublishAlias?: string;
    AutoPublishCodeSha256?: string;
    CodeSigningConfigArn?: string;
    CodeUri?: never;
    DeadLetterQueue?: Function.DeadLetterQueue;
    DeploymentPreference?: Function.DeploymentPreference;
    Description?: string;
    Environment?: Function.FunctionEnvironment;
    EventInvokeConfig?: Function.EventInvokeConfig;
    Events?: Record<string, Function.EventSource>;
    FileSystemConfigs?: Function.FileSystemConfig[];
    FunctionName?: string;
    Handler?: string;
    ImageConfig?: Function.ImageConfig;
    ImageUri?: string;
    InlineCode?: string;
    KmsKeyArn?: string;
    Layers?: string[];
    MemorySize?: number;
    PackageType?: string;
    PermissionsBoundary?: string;
    Policies?: never;
    ProvisionedConcurrencyConfig?: Function.ProvisionedConcurrencyConfig;
    ReservedConcurrentExecutions?: number;
    Role?: string;
    Runtime?: string;
    Tags?: Record<string, string>;
    Timeout?: number;
    Tracing?: string;
    VersionDescription?: string;
    VpcConfig?: Function.VpcConfig;
  }
  export namespace Function {
    export interface Attr {}
    export interface AlexaSkillEvent {
      Variables?: Record<string, string>;
    }
    export interface ApiEvent {
      Auth?: Auth;
      Method: string;
      Path: string;
      RequestModel?: RequestModel;
      RequestParameters?: never;
      RestApiId?: string;
    }
    export interface Auth {
      ApiKeyRequired?: boolean;
      AuthorizationScopes?: string[];
      Authorizer?: string;
      ResourcePolicy?: AuthResourcePolicy;
    }
    export interface AuthResourcePolicy {
      AwsAccountBlacklist?: string[];
      AwsAccountWhitelist?: string[];
      CustomStatements?: any[];
      IntrinsicVpcBlacklist?: string[];
      IntrinsicVpcWhitelist?: string[];
      IntrinsicVpceBlacklist?: string[];
      IntrinsicVpceWhitelist?: string[];
      IpRangeBlacklist?: string[];
      IpRangeWhitelist?: string[];
      SourceVpcBlacklist?: string[];
      SourceVpcWhitelist?: string[];
    }
    export interface BucketSAMPT {
      BucketName: string;
    }
    export interface CloudWatchEventEvent {
      Input?: string;
      InputPath?: string;
      Pattern: any;
    }
    export interface CloudWatchLogsEvent {
      FilterPattern: string;
      LogGroupName: string;
    }
    export interface CollectionSAMPT {
      CollectionId: string;
    }
    export interface DeadLetterQueue {
      TargetArn: string;
      Type: string;
    }
    export interface DeploymentPreference {
      Alarms?: string[];
      Enabled: boolean;
      Hooks?: Hooks;
      Type: string;
    }
    export interface Destination {
      Destination: string;
      Type?: string;
    }
    export interface DestinationConfig {
      OnFailure: Destination;
    }
    export interface DomainSAMPT {
      DomainName: string;
    }
    export interface DynamoDBEvent {
      BatchSize?: number;
      BisectBatchOnFunctionError?: boolean;
      DestinationConfig?: DestinationConfig;
      Enabled?: boolean;
      MaximumBatchingWindowInSeconds?: number;
      MaximumRecordAgeInSeconds?: number;
      MaximumRetryAttempts?: number;
      ParallelizationFactor?: number;
      StartingPosition: string;
      Stream: string;
    }
    export interface EmptySAMPT {}
    export interface EventBridgeRuleEvent {
      EventBusName?: string;
      Input?: string;
      InputPath?: string;
      Pattern: any;
    }
    export interface EventInvokeConfig {
      DestinationConfig?: EventInvokeDestinationConfig;
      MaximumEventAgeInSeconds?: number;
      MaximumRetryAttempts?: number;
    }
    export interface EventInvokeDestinationConfig {
      OnFailure: Destination;
      OnSuccess: Destination;
    }
    export interface EventSource {
      Properties: never;
      Type: string;
    }
    export interface FileSystemConfig {
      Arn?: string;
      LocalMountPath?: string;
    }
    export interface FunctionEnvironment {
      Variables: Record<string, string>;
    }
    export interface FunctionSAMPT {
      FunctionName: string;
    }
    export interface Hooks {
      PostTraffic?: string;
      PreTraffic?: string;
    }
    export interface HttpApiEvent {
      ApiId?: string;
      Auth?: HttpApiFunctionAuth;
      Method?: string;
      Path?: string;
      PayloadFormatVersion?: string;
      RouteSettings?: RouteSettings;
      TimeoutInMillis?: number;
    }
    export interface HttpApiFunctionAuth {
      AuthorizationScopes?: string[];
      Authorizer?: string;
    }
    export interface IAMPolicyDocument {
      Statement: any;
      Version?: string;
    }
    export interface IdentitySAMPT {
      IdentityName: string;
    }
    export interface ImageConfig {
      Command?: string[];
      EntryPoint?: string[];
      WorkingDirectory?: string;
    }
    export interface IoTRuleEvent {
      AwsIotSqlVersion?: string;
      Sql: string;
    }
    export interface KeySAMPT {
      KeyId: string;
    }
    export interface KinesisEvent {
      BatchSize?: number;
      Enabled?: boolean;
      FunctionResponseTypes?: string[];
      StartingPosition: string;
      Stream: string;
    }
    export interface LogGroupSAMPT {
      LogGroupName: string;
    }
    export interface ParameterNameSAMPT {
      ParameterName: string;
    }
    export interface ProvisionedConcurrencyConfig {
      ProvisionedConcurrentExecutions: string;
    }
    export interface QueueSAMPT {
      QueueName: string;
    }
    export interface RequestModel {
      Model: string;
      Required?: boolean;
      ValidateBody?: boolean;
      ValidateParameters?: boolean;
    }
    export interface RequestParameter {
      Caching?: boolean;
      Required?: boolean;
    }
    export interface RouteSettings {
      DataTraceEnabled?: boolean;
      DetailedMetricsEnabled?: boolean;
      LoggingLevel?: string;
      ThrottlingBurstLimit?: number;
      ThrottlingRateLimit?: number;
    }
    export interface S3Event {
      Bucket: string;
      Events: never;
      Filter?: S3NotificationFilter;
    }
    export interface S3KeyFilter {
      Rules: S3KeyFilterRule[];
    }
    export interface S3KeyFilterRule {
      Name: string;
      Value: string;
    }
    export interface S3Location {
      Bucket: string;
      Key: string;
      Version?: number;
    }
    export interface S3NotificationFilter {
      S3Key: S3KeyFilter;
    }
    export interface SAMPolicyTemplate {
      AMIDescribePolicy?: EmptySAMPT;
      AWSSecretsManagerGetSecretValuePolicy?: SecretArnSAMPT;
      CloudFormationDescribeStacksPolicy?: EmptySAMPT;
      CloudWatchPutMetricPolicy?: EmptySAMPT;
      DynamoDBCrudPolicy?: TableSAMPT;
      DynamoDBReadPolicy?: TableSAMPT;
      DynamoDBStreamReadPolicy?: TableStreamSAMPT;
      DynamoDBWritePolicy?: TableSAMPT;
      EC2DescribePolicy?: EmptySAMPT;
      ElasticsearchHttpPostPolicy?: DomainSAMPT;
      FilterLogEventsPolicy?: LogGroupSAMPT;
      KMSDecryptPolicy?: KeySAMPT;
      KinesisCrudPolicy?: StreamSAMPT;
      KinesisStreamReadPolicy?: StreamSAMPT;
      LambdaInvokePolicy?: FunctionSAMPT;
      RekognitionDetectOnlyPolicy?: EmptySAMPT;
      RekognitionLabelsPolicy?: EmptySAMPT;
      RekognitionNoDataAccessPolicy?: CollectionSAMPT;
      RekognitionReadPolicy?: CollectionSAMPT;
      RekognitionWriteOnlyAccessPolicy?: CollectionSAMPT;
      S3CrudPolicy?: BucketSAMPT;
      S3ReadPolicy?: BucketSAMPT;
      S3WritePolicy?: BucketSAMPT;
      SESBulkTemplatedCrudPolicy?: IdentitySAMPT;
      SESCrudPolicy?: IdentitySAMPT;
      SESEmailTemplateCrudPolicy?: EmptySAMPT;
      SESSendBouncePolicy?: IdentitySAMPT;
      SNSCrudPolicy?: TopicSAMPT;
      SNSPublishMessagePolicy?: TopicSAMPT;
      SQSPollerPolicy?: QueueSAMPT;
      SQSSendMessagePolicy?: QueueSAMPT;
      SSMParameterReadPolicy?: ParameterNameSAMPT;
      StepFunctionsExecutionPolicy?: StateMachineSAMPT;
      VPCAccessPolicy?: EmptySAMPT;
    }
    export interface SNSEvent {
      Topic: string;
    }
    export interface SQSEvent {
      BatchSize?: number;
      Enabled?: boolean;
      Queue: string;
    }
    export interface ScheduleEvent {
      Description?: string;
      Enabled?: boolean;
      Input?: string;
      Name?: string;
      Schedule: string;
    }
    export interface SecretArnSAMPT {
      SecretArn: string;
    }
    export interface StateMachineSAMPT {
      StateMachineName: string;
    }
    export interface StreamSAMPT {
      StreamName: string;
    }
    export interface TableSAMPT {
      TableName: string;
    }
    export interface TableStreamSAMPT {
      StreamName: string;
      TableName: string;
    }
    export interface TopicSAMPT {
      TopicName: string;
    }
    export interface VpcConfig {
      SecurityGroupIds: string[];
      SubnetIds: string[];
    }
  }
  export interface HttpApi {
    AccessLogSetting?: HttpApi.AccessLogSetting;
    Auth?: HttpApi.HttpApiAuth;
    CorsConfiguration?: never;
    DefaultRouteSettings?: HttpApi.RouteSettings;
    DefinitionBody?: any;
    DefinitionUri?: never;
    Description?: string;
    DisableExecuteApiEndpoint?: boolean;
    Domain?: HttpApi.HttpApiDomainConfiguration;
    FailOnWarnings?: boolean;
    RouteSettings?: HttpApi.RouteSettings;
    StageName?: string;
    StageVariables?: Record<string, string>;
    Tags?: Record<string, string>;
  }
  export namespace HttpApi {
    export interface Attr {}
    export interface AccessLogSetting {
      DestinationArn?: string;
      Format?: string;
    }
    export interface CorsConfigurationObject {
      AllowCredentials?: boolean;
      AllowHeaders?: string[];
      AllowMethods?: string[];
      AllowOrigins?: string[];
      ExposeHeaders?: string[];
      MaxAge?: number;
    }
    export interface HttpApiAuth {
      Authorizers?: any;
      DefaultAuthorizer?: string;
    }
    export interface HttpApiDomainConfiguration {
      BasePath?: string;
      CertificateArn: string;
      DomainName: string;
      EndpointConfiguration?: string;
      MutualTlsAuthentication?: MutualTlsAuthentication;
      Route53?: Route53Configuration;
      SecurityPolicy?: string;
    }
    export interface MutualTlsAuthentication {
      TruststoreUri?: string;
      TruststoreVersion?: boolean;
    }
    export interface Route53Configuration {
      DistributedDomainName?: string;
      EvaluateTargetHealth?: boolean;
      HostedZoneId?: string;
      HostedZoneName?: string;
      IpV6?: boolean;
    }
    export interface RouteSettings {
      DataTraceEnabled?: boolean;
      DetailedMetricsEnabled?: boolean;
      LoggingLevel?: string;
      ThrottlingBurstLimit?: number;
      ThrottlingRateLimit?: number;
    }
    export interface S3Location {
      Bucket: string;
      Key: string;
      Version: number;
    }
  }
  export interface LayerVersion {
    CompatibleRuntimes?: string[];
    ContentUri?: never;
    Description?: string;
    LayerName?: string;
    LicenseInfo?: string;
    RetentionPolicy?: string;
  }
  export namespace LayerVersion {
    export interface Attr {}
    export interface S3Location {
      Bucket: string;
      Key: string;
      Version?: number;
    }
  }
  export interface SimpleTable {
    PrimaryKey?: SimpleTable.PrimaryKey;
    ProvisionedThroughput?: SimpleTable.ProvisionedThroughput;
    SSESpecification?: SimpleTable.SSESpecification;
    TableName?: string;
    Tags?: Record<string, string>;
  }
  export namespace SimpleTable {
    export interface Attr {}
    export interface PrimaryKey {
      Name?: string;
      Type: string;
    }
    export interface ProvisionedThroughput {
      ReadCapacityUnits?: number;
      WriteCapacityUnits: number;
    }
    export interface SSESpecification {
      SSEEnabled?: boolean;
    }
  }
  export interface StateMachine {
    Definition?: any;
    DefinitionSubstitutions?: Record<string, string>;
    DefinitionUri?: never;
    Events?: Record<string, StateMachine.EventSource>;
    Logging?: StateMachine.LoggingConfiguration;
    Name?: string;
    PermissionsBoundaries?: string;
    Policies?: never;
    Role?: string;
    Tags?: Record<string, string>;
    Tracing?: StateMachine.TracingConfiguration;
    Type?: string;
  }
  export namespace StateMachine {
    export interface Attr {}
    export interface ApiEvent {
      Method: string;
      Path: string;
      RestApiId?: string;
    }
    export interface CloudWatchEventEvent {
      EventBusName?: string;
      Input?: string;
      InputPath?: string;
      Pattern: any;
    }
    export interface CloudWatchLogsLogGroup {
      LogGroupArn: string;
    }
    export interface EventBridgeRuleEvent {
      EventBusName?: string;
      Input?: string;
      InputPath?: string;
      Pattern: any;
    }
    export interface EventSource {
      Properties: never;
      Type: string;
    }
    export interface FunctionSAMPT {
      FunctionName: string;
    }
    export interface IAMPolicyDocument {
      Statement: any;
      Version: string;
    }
    export interface LogDestination {
      CloudWatchLogsLogGroup: CloudWatchLogsLogGroup;
    }
    export interface LoggingConfiguration {
      Destinations: LogDestination[];
      IncludeExecutionData: boolean;
      Level: string;
    }
    export interface S3Location {
      Bucket: string;
      Key: string;
      Version?: number;
    }
    export interface SAMPolicyTemplate {
      LambdaInvokePolicy?: FunctionSAMPT;
      StepFunctionsExecutionPolicy?: StateMachineSAMPT;
    }
    export interface ScheduleEvent {
      Input?: string;
      Schedule: string;
    }
    export interface StateMachineSAMPT {
      StateMachineName: string;
    }
    export interface TracingConfiguration {
      Enabled?: boolean;
    }
  }
}
export namespace ServiceCatalog {
  export interface AcceptedPortfolioShare {
    AcceptLanguage?: string;
    PortfolioId: string;
  }
  export interface CloudFormationProduct {
    AcceptLanguage?: string;
    Description?: string;
    Distributor?: string;
    Name: string;
    Owner: string;
    ProvisioningArtifactParameters: CloudFormationProduct.ProvisioningArtifactProperties[];
    ReplaceProvisioningArtifacts?: boolean;
    SupportDescription?: string;
    SupportEmail?: string;
    SupportUrl?: string;
    Tags?: Tag[];
  }
  export namespace CloudFormationProduct {
    export interface Attr {
      ProductName: string;
      ProvisioningArtifactIds: string;
      ProvisioningArtifactNames: string;
    }
    export interface ProvisioningArtifactProperties {
      Description?: string;
      DisableTemplateValidation?: boolean;
      Info: any;
      Name?: string;
    }
  }
  export interface CloudFormationProvisionedProduct {
    AcceptLanguage?: string;
    NotificationArns?: string[];
    PathId?: string;
    PathName?: string;
    ProductId?: string;
    ProductName?: string;
    ProvisionedProductName?: string;
    ProvisioningArtifactId?: string;
    ProvisioningArtifactName?: string;
    ProvisioningParameters?: CloudFormationProvisionedProduct.ProvisioningParameter[];
    ProvisioningPreferences?: CloudFormationProvisionedProduct.ProvisioningPreferences;
    Tags?: Tag[];
  }
  export namespace CloudFormationProvisionedProduct {
    export interface Attr {
      CloudformationStackArn: string;
      Outputs: Record<string, string>;
      ProvisionedProductId: string;
      RecordId: string;
    }
    export interface ProvisioningParameter {
      Key: string;
      Value: string;
    }
    export interface ProvisioningPreferences {
      StackSetAccounts?: string[];
      StackSetFailureToleranceCount?: number;
      StackSetFailureTolerancePercentage?: number;
      StackSetMaxConcurrencyCount?: number;
      StackSetMaxConcurrencyPercentage?: number;
      StackSetOperationType?: string;
      StackSetRegions?: string[];
    }
  }
  export interface LaunchNotificationConstraint {
    AcceptLanguage?: string;
    Description?: string;
    NotificationArns: string[];
    PortfolioId: string;
    ProductId: string;
  }
  export interface LaunchRoleConstraint {
    AcceptLanguage?: string;
    Description?: string;
    LocalRoleName?: string;
    PortfolioId: string;
    ProductId: string;
    RoleArn?: string;
  }
  export interface LaunchTemplateConstraint {
    AcceptLanguage?: string;
    Description?: string;
    PortfolioId: string;
    ProductId: string;
    Rules: string;
  }
  export interface Portfolio {
    AcceptLanguage?: string;
    Description?: string;
    DisplayName: string;
    ProviderName: string;
    Tags?: Tag[];
  }
  export interface PortfolioPrincipalAssociation {
    AcceptLanguage?: string;
    PortfolioId: string;
    PrincipalARN: string;
    PrincipalType: string;
  }
  export interface PortfolioProductAssociation {
    AcceptLanguage?: string;
    PortfolioId: string;
    ProductId: string;
    SourcePortfolioId?: string;
  }
  export interface PortfolioShare {
    AcceptLanguage?: string;
    AccountId: string;
    PortfolioId: string;
    ShareTagOptions?: boolean;
  }
  export interface ResourceUpdateConstraint {
    AcceptLanguage?: string;
    Description?: string;
    PortfolioId: string;
    ProductId: string;
    TagUpdateOnProvisionedProduct: string;
  }
  export interface ServiceAction {
    AcceptLanguage?: string;
    Definition: ServiceAction.DefinitionParameter[];
    DefinitionType: string;
    Description?: string;
    Name: string;
  }
  export namespace ServiceAction {
    export interface Attr {
      Id: string;
    }
    export interface DefinitionParameter {
      Key: string;
      Value: string;
    }
  }
  export interface ServiceActionAssociation {
    ProductId: string;
    ProvisioningArtifactId: string;
    ServiceActionId: string;
  }
  export interface StackSetConstraint {
    AcceptLanguage?: string;
    AccountList: string[];
    AdminRole: string;
    Description: string;
    ExecutionRole: string;
    PortfolioId: string;
    ProductId: string;
    RegionList: string[];
    StackInstanceControl: string;
  }
  export interface TagOption {
    Active?: boolean;
    Key: string;
    Value: string;
  }
  export interface TagOptionAssociation {
    ResourceId: string;
    TagOptionId: string;
  }
}
export namespace ServiceCatalogAppRegistry {
  export interface Application {
    Description?: string;
    Name: string;
    Tags?: Record<string, string>;
  }
  export interface AttributeGroup {
    Attributes: any;
    Description?: string;
    Name: string;
    Tags?: Record<string, string>;
  }
  export interface AttributeGroupAssociation {
    Application: string;
    AttributeGroup: string;
  }
  export interface ResourceAssociation {
    Application: string;
    Resource: string;
    ResourceType: string;
  }
}
export namespace ServiceDiscovery {
  export interface HttpNamespace {
    Description?: string;
    Name: string;
    Tags?: Tag[];
  }
  export interface Instance {
    InstanceAttributes: any;
    InstanceId?: string;
    ServiceId: string;
  }
  export interface PrivateDnsNamespace {
    Description?: string;
    Name: string;
    Properties?: PrivateDnsNamespace.Properties;
    Tags?: Tag[];
    Vpc: string;
  }
  export namespace PrivateDnsNamespace {
    export interface Attr {
      Arn: string;
      HostedZoneId: string;
      Id: string;
    }
    export interface PrivateDnsPropertiesMutable {
      SOA?: SOA;
    }
    export interface Properties {
      DnsProperties?: PrivateDnsPropertiesMutable;
    }
    export interface SOA {
      TTL?: number;
    }
  }
  export interface PublicDnsNamespace {
    Description?: string;
    Name: string;
    Properties?: PublicDnsNamespace.Properties;
    Tags?: Tag[];
  }
  export namespace PublicDnsNamespace {
    export interface Attr {
      Arn: string;
      HostedZoneId: string;
      Id: string;
    }
    export interface Properties {
      DnsProperties?: PublicDnsPropertiesMutable;
    }
    export interface PublicDnsPropertiesMutable {
      SOA?: SOA;
    }
    export interface SOA {
      TTL?: number;
    }
  }
  export interface Service {
    Description?: string;
    DnsConfig?: Service.DnsConfig;
    HealthCheckConfig?: Service.HealthCheckConfig;
    HealthCheckCustomConfig?: Service.HealthCheckCustomConfig;
    Name?: string;
    NamespaceId?: string;
    Tags?: Tag[];
    Type?: string;
  }
  export namespace Service {
    export interface Attr {
      Arn: string;
      Id: string;
      Name: string;
    }
    export interface DnsConfig {
      DnsRecords: DnsRecord[];
      NamespaceId?: string;
      RoutingPolicy?: string;
    }
    export interface DnsRecord {
      TTL: number;
      Type: string;
    }
    export interface HealthCheckConfig {
      FailureThreshold?: number;
      ResourcePath?: string;
      Type: string;
    }
    export interface HealthCheckCustomConfig {
      FailureThreshold?: number;
    }
  }
}
export namespace Signer {
  export interface ProfilePermission {
    Action: string;
    Principal: string;
    ProfileName: string;
    ProfileVersion?: string;
    StatementId: string;
  }
  export interface SigningProfile {
    PlatformId: string;
    SignatureValidityPeriod?: SigningProfile.SignatureValidityPeriod;
    Tags?: Tag[];
  }
  export namespace SigningProfile {
    export interface Attr {
      Arn: string;
      ProfileName: string;
      ProfileVersion: string;
      ProfileVersionArn: string;
    }
    export interface SignatureValidityPeriod {
      Type?: string;
      Value?: number;
    }
  }
}
export namespace StepFunctions {
  export interface Activity {
    Name: string;
    Tags?: Activity.TagsEntry[];
  }
  export namespace Activity {
    export interface Attr {
      Arn: string;
      Name: string;
    }
    export interface TagsEntry {
      Key: string;
      Value: string;
    }
  }
  export interface StateMachine {
    Definition?: any;
    DefinitionS3Location?: StateMachine.S3Location;
    DefinitionString?: string;
    DefinitionSubstitutions?: Record<string, any>;
    LoggingConfiguration?: StateMachine.LoggingConfiguration;
    RoleArn: string;
    StateMachineName?: string;
    StateMachineType?: string;
    Tags?: StateMachine.TagsEntry[];
    TracingConfiguration?: StateMachine.TracingConfiguration;
  }
  export namespace StateMachine {
    export interface Attr {
      Arn: string;
      Name: string;
    }
    export interface CloudWatchLogsLogGroup {
      LogGroupArn?: string;
    }
    export interface LogDestination {
      CloudWatchLogsLogGroup?: CloudWatchLogsLogGroup;
    }
    export interface LoggingConfiguration {
      Destinations?: LogDestination[];
      IncludeExecutionData?: boolean;
      Level?: string;
    }
    export interface S3Location {
      Bucket: string;
      Key: string;
      Version?: string;
    }
    export interface TagsEntry {
      Key: string;
      Value: string;
    }
    export interface TracingConfiguration {
      Enabled?: boolean;
    }
  }
}
export namespace SupportApp {
  export interface AccountAlias {
    AccountAlias: string;
  }
  export interface SlackChannelConfiguration {
    ChannelId: string;
    ChannelName?: string;
    ChannelRoleArn: string;
    NotifyOnAddCorrespondenceToCase?: boolean;
    NotifyOnCaseSeverity: string;
    NotifyOnCreateOrReopenCase?: boolean;
    NotifyOnResolveCase?: boolean;
    TeamId: string;
  }
  export interface SlackWorkspaceConfiguration {
    TeamId: string;
    VersionId?: string;
  }
}
export namespace Synthetics {
  export interface Canary {
    ArtifactConfig?: Canary.ArtifactConfig;
    ArtifactS3Location: string;
    Code: Canary.Code;
    DeleteLambdaResourcesOnCanaryDeletion?: boolean;
    ExecutionRoleArn: string;
    FailureRetentionPeriod?: number;
    Name: string;
    RunConfig?: Canary.RunConfig;
    RuntimeVersion: string;
    Schedule: Canary.Schedule;
    StartCanaryAfterCreation: boolean;
    SuccessRetentionPeriod?: number;
    Tags?: Tag[];
    VPCConfig?: Canary.VPCConfig;
    VisualReference?: Canary.VisualReference;
  }
  export namespace Canary {
    export interface Attr {
      Id: string;
      State: string;
    }
    export interface ArtifactConfig {
      S3Encryption?: S3Encryption;
    }
    export interface BaseScreenshot {
      IgnoreCoordinates?: string[];
      ScreenshotName: string;
    }
    export interface Code {
      Handler: string;
      S3Bucket?: string;
      S3Key?: string;
      S3ObjectVersion?: string;
      Script?: string;
    }
    export interface RunConfig {
      ActiveTracing?: boolean;
      EnvironmentVariables?: Record<string, string>;
      MemoryInMB?: number;
      TimeoutInSeconds?: number;
    }
    export interface S3Encryption {
      EncryptionMode?: string;
      KmsKeyArn?: string;
    }
    export interface Schedule {
      DurationInSeconds?: string;
      Expression: string;
    }
    export interface VPCConfig {
      SecurityGroupIds: string[];
      SubnetIds: string[];
      VpcId?: string;
    }
    export interface VisualReference {
      BaseCanaryRunId: string;
      BaseScreenshots?: BaseScreenshot[];
    }
  }
  export interface Group {
    Name: string;
    ResourceArns?: string[];
    Tags?: Tag[];
  }
}
export namespace Timestream {
  export interface Database {
    DatabaseName?: string;
    KmsKeyId?: string;
    Tags?: Tag[];
  }
  export interface ScheduledQuery {
    ClientToken?: string;
    ErrorReportConfiguration: ScheduledQuery.ErrorReportConfiguration;
    KmsKeyId?: string;
    NotificationConfiguration: ScheduledQuery.NotificationConfiguration;
    QueryString: string;
    ScheduleConfiguration: ScheduledQuery.ScheduleConfiguration;
    ScheduledQueryExecutionRoleArn: string;
    ScheduledQueryName?: string;
    Tags?: Tag[];
    TargetConfiguration?: ScheduledQuery.TargetConfiguration;
  }
  export namespace ScheduledQuery {
    export interface Attr {
      Arn: string;
      SQErrorReportConfiguration: string;
      SQKmsKeyId: string;
      SQName: string;
      SQNotificationConfiguration: string;
      SQQueryString: string;
      SQScheduleConfiguration: string;
      SQScheduledQueryExecutionRoleArn: string;
      SQTargetConfiguration: string;
    }
    export interface DimensionMapping {
      DimensionValueType: string;
      Name: string;
    }
    export interface ErrorReportConfiguration {
      S3Configuration: S3Configuration;
    }
    export interface MixedMeasureMapping {
      MeasureName?: string;
      MeasureValueType: string;
      MultiMeasureAttributeMappings?: MultiMeasureAttributeMapping[];
      SourceColumn?: string;
      TargetMeasureName?: string;
    }
    export interface MultiMeasureAttributeMapping {
      MeasureValueType: string;
      SourceColumn: string;
      TargetMultiMeasureAttributeName?: string;
    }
    export interface MultiMeasureMappings {
      MultiMeasureAttributeMappings: MultiMeasureAttributeMapping[];
      TargetMultiMeasureName?: string;
    }
    export interface NotificationConfiguration {
      SnsConfiguration: SnsConfiguration;
    }
    export interface S3Configuration {
      BucketName: string;
      EncryptionOption?: string;
      ObjectKeyPrefix?: string;
    }
    export interface ScheduleConfiguration {
      ScheduleExpression: string;
    }
    export interface SnsConfiguration {
      TopicArn: string;
    }
    export interface TargetConfiguration {
      TimestreamConfiguration: TimestreamConfiguration;
    }
    export interface TimestreamConfiguration {
      DatabaseName: string;
      DimensionMappings: DimensionMapping[];
      MeasureNameColumn?: string;
      MixedMeasureMappings?: MixedMeasureMapping[];
      MultiMeasureMappings?: MultiMeasureMappings;
      TableName: string;
      TimeColumn: string;
    }
  }
  export interface Table {
    DatabaseName: string;
    MagneticStoreWriteProperties?: Table.MagneticStoreWriteProperties;
    RetentionProperties?: Table.RetentionProperties;
    TableName?: string;
    Tags?: Tag[];
  }
  export namespace Table {
    export interface Attr {
      Arn: string;
      Name: string;
    }
    export interface MagneticStoreRejectedDataLocation {
      S3Configuration?: S3Configuration;
    }
    export interface MagneticStoreWriteProperties {
      EnableMagneticStoreWrites: boolean;
      MagneticStoreRejectedDataLocation?: MagneticStoreRejectedDataLocation;
    }
    export interface RetentionProperties {
      MagneticStoreRetentionPeriodInDays?: string;
      MemoryStoreRetentionPeriodInHours?: string;
    }
    export interface S3Configuration {
      BucketName: string;
      EncryptionOption: string;
      KmsKeyId?: string;
      ObjectKeyPrefix?: string;
    }
  }
}
export namespace Transfer {
  export interface Agreement {
    AccessRole: string;
    BaseDirectory: string;
    Description?: string;
    LocalProfileId: string;
    PartnerProfileId: string;
    ServerId: string;
    Status?: string;
    Tags?: Tag[];
  }
  export interface Certificate {
    ActiveDate?: string;
    Certificate: string;
    CertificateChain?: string;
    Description?: string;
    InactiveDate?: string;
    PrivateKey?: string;
    Tags?: Tag[];
    Usage: string;
  }
  export interface Connector {
    AccessRole: string;
    As2Config: any;
    LoggingRole?: string;
    Tags?: Tag[];
    Url: string;
  }
  export namespace Connector {
    export interface Attr {
      Arn: string;
      ConnectorId: string;
    }
    export interface As2Config {
      Compression?: string;
      EncryptionAlgorithm?: string;
      LocalProfileId?: string;
      MdnResponse?: string;
      MdnSigningAlgorithm?: string;
      MessageSubject?: string;
      PartnerProfileId?: string;
      SigningAlgorithm?: string;
    }
  }
  export interface Profile {
    As2Id: string;
    CertificateIds?: string[];
    ProfileType: string;
    Tags?: Tag[];
  }
  export interface Server {
    Certificate?: string;
    Domain?: string;
    EndpointDetails?: Server.EndpointDetails;
    EndpointType?: string;
    IdentityProviderDetails?: Server.IdentityProviderDetails;
    IdentityProviderType?: string;
    LoggingRole?: string;
    PostAuthenticationLoginBanner?: string;
    PreAuthenticationLoginBanner?: string;
    ProtocolDetails?: Server.ProtocolDetails;
    Protocols?: Server.Protocol[];
    SecurityPolicyName?: string;
    Tags?: Tag[];
    WorkflowDetails?: Server.WorkflowDetails;
  }
  export namespace Server {
    export interface Attr {
      Arn: string;
      ServerId: string;
    }
    export interface As2Transport {}
    export interface EndpointDetails {
      AddressAllocationIds?: string[];
      SecurityGroupIds?: string[];
      SubnetIds?: string[];
      VpcEndpointId?: string;
      VpcId?: string;
    }
    export interface IdentityProviderDetails {
      DirectoryId?: string;
      Function?: string;
      InvocationRole?: string;
      Url?: string;
    }
    export interface Protocol {}
    export interface ProtocolDetails {
      As2Transports?: As2Transport[];
      PassiveIp?: string;
      SetStatOption?: string;
      TlsSessionResumptionMode?: string;
    }
    export interface WorkflowDetail {
      ExecutionRole: string;
      WorkflowId: string;
    }
    export interface WorkflowDetails {
      OnPartialUpload?: WorkflowDetail[];
      OnUpload?: WorkflowDetail[];
    }
  }
  export interface User {
    HomeDirectory?: string;
    HomeDirectoryMappings?: User.HomeDirectoryMapEntry[];
    HomeDirectoryType?: string;
    Policy?: string;
    PosixProfile?: User.PosixProfile;
    Role: string;
    ServerId: string;
    SshPublicKeys?: User.SshPublicKey[];
    Tags?: Tag[];
    UserName: string;
  }
  export namespace User {
    export interface Attr {
      Arn: string;
      ServerId: string;
      UserName: string;
    }
    export interface HomeDirectoryMapEntry {
      Entry: string;
      Target: string;
    }
    export interface PosixProfile {
      Gid: number;
      SecondaryGids?: number[];
      Uid: number;
    }
    export interface SshPublicKey {}
  }
  export interface Workflow {
    Description?: string;
    OnExceptionSteps?: Workflow.WorkflowStep[];
    Steps: Workflow.WorkflowStep[];
    Tags?: Tag[];
  }
  export namespace Workflow {
    export interface Attr {
      Arn: string;
      WorkflowId: string;
    }
    export interface CopyStepDetails {
      DestinationFileLocation?: S3FileLocation;
      Name?: string;
      OverwriteExisting?: string;
      SourceFileLocation?: string;
    }
    export interface CustomStepDetails {
      Name?: string;
      SourceFileLocation?: string;
      Target?: string;
      TimeoutSeconds?: number;
    }
    export interface DecryptStepDetails {
      DestinationFileLocation?: InputFileLocation;
      Name?: string;
      OverwriteExisting?: string;
      SourceFileLocation?: string;
      Type?: string;
    }
    export interface DeleteStepDetails {
      Name?: string;
      SourceFileLocation?: string;
    }
    export interface EfsInputFileLocation {
      FileSystemId?: string;
      Path?: string;
    }
    export interface InputFileLocation {
      EfsFileLocation?: EfsInputFileLocation;
      S3FileLocation?: S3InputFileLocation;
    }
    export interface S3FileLocation {
      S3FileLocation?: S3InputFileLocation;
    }
    export interface S3InputFileLocation {
      Bucket?: string;
      Key?: string;
    }
    export interface S3Tag {
      Key: string;
      Value: string;
    }
    export interface TagStepDetails {
      Name?: string;
      SourceFileLocation?: string;
      Tags?: S3Tag[];
    }
    export interface WorkflowStep {
      CopyStepDetails?: any;
      CustomStepDetails?: any;
      DecryptStepDetails?: DecryptStepDetails;
      DeleteStepDetails?: any;
      TagStepDetails?: any;
      Type?: string;
    }
  }
}
export namespace VoiceID {
  export interface Domain {
    Description?: string;
    Name: string;
    ServerSideEncryptionConfiguration: Domain.ServerSideEncryptionConfiguration;
    Tags?: Tag[];
  }
  export namespace Domain {
    export interface Attr {
      DomainId: string;
    }
    export interface ServerSideEncryptionConfiguration {
      KmsKeyId: string;
    }
  }
}
export namespace WAF {
  export interface ByteMatchSet {
    ByteMatchTuples?: ByteMatchSet.ByteMatchTuple[];
    Name: string;
  }
  export namespace ByteMatchSet {
    export interface Attr {}
    export interface ByteMatchTuple {
      FieldToMatch: FieldToMatch;
      PositionalConstraint: string;
      TargetString?: string;
      TargetStringBase64?: string;
      TextTransformation: string;
    }
    export interface FieldToMatch {
      Data?: string;
      Type: string;
    }
  }
  export interface IPSet {
    IPSetDescriptors?: IPSet.IPSetDescriptor[];
    Name: string;
  }
  export namespace IPSet {
    export interface Attr {}
    export interface IPSetDescriptor {
      Type: string;
      Value: string;
    }
  }
  export interface Rule {
    MetricName: string;
    Name: string;
    Predicates?: Rule.Predicate[];
  }
  export namespace Rule {
    export interface Attr {}
    export interface Predicate {
      DataId: string;
      Negated: boolean;
      Type: string;
    }
  }
  export interface SizeConstraintSet {
    Name: string;
    SizeConstraints: SizeConstraintSet.SizeConstraint[];
  }
  export namespace SizeConstraintSet {
    export interface Attr {}
    export interface FieldToMatch {
      Data?: string;
      Type: string;
    }
    export interface SizeConstraint {
      ComparisonOperator: string;
      FieldToMatch: FieldToMatch;
      Size: number;
      TextTransformation: string;
    }
  }
  export interface SqlInjectionMatchSet {
    Name: string;
    SqlInjectionMatchTuples?: SqlInjectionMatchSet.SqlInjectionMatchTuple[];
  }
  export namespace SqlInjectionMatchSet {
    export interface Attr {}
    export interface FieldToMatch {
      Data?: string;
      Type: string;
    }
    export interface SqlInjectionMatchTuple {
      FieldToMatch: FieldToMatch;
      TextTransformation: string;
    }
  }
  export interface WebACL {
    DefaultAction: WebACL.WafAction;
    MetricName: string;
    Name: string;
    Rules?: WebACL.ActivatedRule[];
  }
  export namespace WebACL {
    export interface Attr {}
    export interface ActivatedRule {
      Action?: WafAction;
      Priority: number;
      RuleId: string;
    }
    export interface WafAction {
      Type: string;
    }
  }
  export interface XssMatchSet {
    Name: string;
    XssMatchTuples: XssMatchSet.XssMatchTuple[];
  }
  export namespace XssMatchSet {
    export interface Attr {}
    export interface FieldToMatch {
      Data?: string;
      Type: string;
    }
    export interface XssMatchTuple {
      FieldToMatch: FieldToMatch;
      TextTransformation: string;
    }
  }
}
export namespace WAFRegional {
  export interface ByteMatchSet {
    ByteMatchTuples?: ByteMatchSet.ByteMatchTuple[];
    Name: string;
  }
  export namespace ByteMatchSet {
    export interface Attr {}
    export interface ByteMatchTuple {
      FieldToMatch: FieldToMatch;
      PositionalConstraint: string;
      TargetString?: string;
      TargetStringBase64?: string;
      TextTransformation: string;
    }
    export interface FieldToMatch {
      Data?: string;
      Type: string;
    }
  }
  export interface GeoMatchSet {
    GeoMatchConstraints?: GeoMatchSet.GeoMatchConstraint[];
    Name: string;
  }
  export namespace GeoMatchSet {
    export interface Attr {}
    export interface GeoMatchConstraint {
      Type: string;
      Value: string;
    }
  }
  export interface IPSet {
    IPSetDescriptors?: IPSet.IPSetDescriptor[];
    Name: string;
  }
  export namespace IPSet {
    export interface Attr {}
    export interface IPSetDescriptor {
      Type: string;
      Value: string;
    }
  }
  export interface RateBasedRule {
    MatchPredicates?: RateBasedRule.Predicate[];
    MetricName: string;
    Name: string;
    RateKey: string;
    RateLimit: number;
  }
  export namespace RateBasedRule {
    export interface Attr {}
    export interface Predicate {
      DataId: string;
      Negated: boolean;
      Type: string;
    }
  }
  export interface RegexPatternSet {
    Name: string;
    RegexPatternStrings: string[];
  }
  export interface Rule {
    MetricName: string;
    Name: string;
    Predicates?: Rule.Predicate[];
  }
  export namespace Rule {
    export interface Attr {}
    export interface Predicate {
      DataId: string;
      Negated: boolean;
      Type: string;
    }
  }
  export interface SizeConstraintSet {
    Name: string;
    SizeConstraints?: SizeConstraintSet.SizeConstraint[];
  }
  export namespace SizeConstraintSet {
    export interface Attr {}
    export interface FieldToMatch {
      Data?: string;
      Type: string;
    }
    export interface SizeConstraint {
      ComparisonOperator: string;
      FieldToMatch: FieldToMatch;
      Size: number;
      TextTransformation: string;
    }
  }
  export interface SqlInjectionMatchSet {
    Name: string;
    SqlInjectionMatchTuples?: SqlInjectionMatchSet.SqlInjectionMatchTuple[];
  }
  export namespace SqlInjectionMatchSet {
    export interface Attr {}
    export interface FieldToMatch {
      Data?: string;
      Type: string;
    }
    export interface SqlInjectionMatchTuple {
      FieldToMatch: FieldToMatch;
      TextTransformation: string;
    }
  }
  export interface WebACL {
    DefaultAction: WebACL.Action;
    MetricName: string;
    Name: string;
    Rules?: WebACL.Rule[];
  }
  export namespace WebACL {
    export interface Attr {}
    export interface Action {
      Type: string;
    }
    export interface Rule {
      Action: Action;
      Priority: number;
      RuleId: string;
    }
  }
  export interface WebACLAssociation {
    ResourceArn: string;
    WebACLId: string;
  }
  export interface XssMatchSet {
    Name: string;
    XssMatchTuples?: XssMatchSet.XssMatchTuple[];
  }
  export namespace XssMatchSet {
    export interface Attr {}
    export interface FieldToMatch {
      Data?: string;
      Type: string;
    }
    export interface XssMatchTuple {
      FieldToMatch: FieldToMatch;
      TextTransformation: string;
    }
  }
}
export namespace WAFv2 {
  export interface IPSet {
    Addresses: string[];
    Description?: string;
    IPAddressVersion: string;
    Name?: string;
    Scope: string;
    Tags?: Tag[];
  }
  export interface LoggingConfiguration {
    LogDestinationConfigs: string[];
    LoggingFilter?: any;
    RedactedFields?: LoggingConfiguration.FieldToMatch[];
    ResourceArn: string;
  }
  export namespace LoggingConfiguration {
    export interface Attr {
      ManagedByFirewallManager: boolean;
    }
    export interface ActionCondition {
      Action: string;
    }
    export interface Condition {
      ActionCondition?: ActionCondition;
      LabelNameCondition?: LabelNameCondition;
    }
    export interface FieldToMatch {
      JsonBody?: any;
      Method?: any;
      QueryString?: any;
      SingleHeader?: any;
      UriPath?: any;
    }
    export interface Filter {
      Behavior: string;
      Conditions: Condition[];
      Requirement: string;
    }
    export interface JsonBody {
      InvalidFallbackBehavior?: string;
      MatchPattern: MatchPattern;
      MatchScope: string;
    }
    export interface LabelNameCondition {
      LabelName: string;
    }
    export interface LoggingFilter {
      DefaultBehavior: string;
      Filters: Filter[];
    }
    export interface MatchPattern {
      All?: any;
      IncludedPaths?: string[];
    }
    export interface SingleHeader {
      Name: string;
    }
  }
  export interface RegexPatternSet {
    Description?: string;
    Name?: string;
    RegularExpressionList: string[];
    Scope: string;
    Tags?: Tag[];
  }
  export interface RuleGroup {
    AvailableLabels?: RuleGroup.LabelSummary[];
    Capacity: number;
    ConsumedLabels?: RuleGroup.LabelSummary[];
    CustomResponseBodies?: Record<string, RuleGroup.CustomResponseBody>;
    Description?: string;
    Name?: string;
    Rules?: RuleGroup.Rule[];
    Scope: string;
    Tags?: Tag[];
    VisibilityConfig: RuleGroup.VisibilityConfig;
  }
  export namespace RuleGroup {
    export interface Attr {
      Arn: string;
      Id: string;
      LabelNamespace: string;
    }
    export interface Allow {
      CustomRequestHandling?: CustomRequestHandling;
    }
    export interface AndStatement {
      Statements: Statement[];
    }
    export interface Block {
      CustomResponse?: CustomResponse;
    }
    export interface Body {
      OversizeHandling?: string;
    }
    export interface ByteMatchStatement {
      FieldToMatch: FieldToMatch;
      PositionalConstraint: string;
      SearchString?: string;
      SearchStringBase64?: string;
      TextTransformations: TextTransformation[];
    }
    export interface Captcha {
      CustomRequestHandling?: CustomRequestHandling;
    }
    export interface CaptchaConfig {
      ImmunityTimeProperty?: ImmunityTimeProperty;
    }
    export interface Challenge {
      CustomRequestHandling?: CustomRequestHandling;
    }
    export interface ChallengeConfig {
      ImmunityTimeProperty?: ImmunityTimeProperty;
    }
    export interface CookieMatchPattern {
      All?: any;
      ExcludedCookies?: string[];
      IncludedCookies?: string[];
    }
    export interface Cookies {
      MatchPattern: CookieMatchPattern;
      MatchScope: string;
      OversizeHandling: string;
    }
    export interface Count {
      CustomRequestHandling?: CustomRequestHandling;
    }
    export interface CustomHTTPHeader {
      Name: string;
      Value: string;
    }
    export interface CustomRequestHandling {
      InsertHeaders: CustomHTTPHeader[];
    }
    export interface CustomResponse {
      CustomResponseBodyKey?: string;
      ResponseCode: number;
      ResponseHeaders?: CustomHTTPHeader[];
    }
    export interface CustomResponseBody {
      Content: string;
      ContentType: string;
    }
    export interface FieldToMatch {
      AllQueryArguments?: any;
      Body?: Body;
      Cookies?: Cookies;
      Headers?: Headers;
      JsonBody?: JsonBody;
      Method?: any;
      QueryString?: any;
      SingleHeader?: any;
      SingleQueryArgument?: any;
      UriPath?: any;
    }
    export interface ForwardedIPConfiguration {
      FallbackBehavior: string;
      HeaderName: string;
    }
    export interface GeoMatchStatement {
      CountryCodes?: string[];
      ForwardedIPConfig?: ForwardedIPConfiguration;
    }
    export interface HeaderMatchPattern {
      All?: any;
      ExcludedHeaders?: string[];
      IncludedHeaders?: string[];
    }
    export interface Headers {
      MatchPattern: HeaderMatchPattern;
      MatchScope: string;
      OversizeHandling: string;
    }
    export interface IPSetForwardedIPConfiguration {
      FallbackBehavior: string;
      HeaderName: string;
      Position: string;
    }
    export interface IPSetReferenceStatement {
      Arn: string;
      IPSetForwardedIPConfig?: IPSetForwardedIPConfiguration;
    }
    export interface ImmunityTimeProperty {
      ImmunityTime: number;
    }
    export interface JsonBody {
      InvalidFallbackBehavior?: string;
      MatchPattern: JsonMatchPattern;
      MatchScope: string;
      OversizeHandling?: string;
    }
    export interface JsonMatchPattern {
      All?: any;
      IncludedPaths?: string[];
    }
    export interface Label {
      Name: string;
    }
    export interface LabelMatchStatement {
      Key: string;
      Scope: string;
    }
    export interface LabelSummary {
      Name?: string;
    }
    export interface NotStatement {
      Statement: Statement;
    }
    export interface OrStatement {
      Statements: Statement[];
    }
    export interface RateBasedStatement {
      AggregateKeyType: string;
      ForwardedIPConfig?: ForwardedIPConfiguration;
      Limit: number;
      ScopeDownStatement?: Statement;
    }
    export interface RegexMatchStatement {
      FieldToMatch: FieldToMatch;
      RegexString: string;
      TextTransformations: TextTransformation[];
    }
    export interface RegexPatternSetReferenceStatement {
      Arn: string;
      FieldToMatch: FieldToMatch;
      TextTransformations: TextTransformation[];
    }
    export interface Rule {
      Action?: RuleAction;
      CaptchaConfig?: CaptchaConfig;
      ChallengeConfig?: ChallengeConfig;
      Name: string;
      Priority: number;
      RuleLabels?: Label[];
      Statement: Statement;
      VisibilityConfig: VisibilityConfig;
    }
    export interface RuleAction {
      Allow?: any;
      Block?: any;
      Captcha?: any;
      Challenge?: Challenge;
      Count?: any;
    }
    export interface SingleHeader {
      Name: string;
    }
    export interface SingleQueryArgument {
      Name: string;
    }
    export interface SizeConstraintStatement {
      ComparisonOperator: string;
      FieldToMatch: FieldToMatch;
      Size: number;
      TextTransformations: TextTransformation[];
    }
    export interface SqliMatchStatement {
      FieldToMatch: FieldToMatch;
      SensitivityLevel?: string;
      TextTransformations: TextTransformation[];
    }
    export interface Statement {
      AndStatement?: AndStatement;
      ByteMatchStatement?: ByteMatchStatement;
      GeoMatchStatement?: GeoMatchStatement;
      IPSetReferenceStatement?: IPSetReferenceStatement;
      LabelMatchStatement?: LabelMatchStatement;
      NotStatement?: NotStatement;
      OrStatement?: OrStatement;
      RateBasedStatement?: RateBasedStatement;
      RegexMatchStatement?: RegexMatchStatement;
      RegexPatternSetReferenceStatement?: RegexPatternSetReferenceStatement;
      SizeConstraintStatement?: SizeConstraintStatement;
      SqliMatchStatement?: SqliMatchStatement;
      XssMatchStatement?: XssMatchStatement;
    }
    export interface TextTransformation {
      Priority: number;
      Type: string;
    }
    export interface VisibilityConfig {
      CloudWatchMetricsEnabled: boolean;
      MetricName: string;
      SampledRequestsEnabled: boolean;
    }
    export interface XssMatchStatement {
      FieldToMatch: FieldToMatch;
      TextTransformations: TextTransformation[];
    }
  }
  export interface WebACL {
    CaptchaConfig?: WebACL.CaptchaConfig;
    ChallengeConfig?: WebACL.ChallengeConfig;
    CustomResponseBodies?: Record<string, WebACL.CustomResponseBody>;
    DefaultAction: WebACL.DefaultAction;
    Description?: string;
    Name?: string;
    Rules?: WebACL.Rule[];
    Scope: string;
    Tags?: Tag[];
    TokenDomains?: string[];
    VisibilityConfig: WebACL.VisibilityConfig;
  }
  export namespace WebACL {
    export interface Attr {
      Arn: string;
      Capacity: number;
      Id: string;
      LabelNamespace: string;
    }
    export interface AWSManagedRulesBotControlRuleSet {
      InspectionLevel: string;
    }
    export interface AllowAction {
      CustomRequestHandling?: CustomRequestHandling;
    }
    export interface AndStatement {
      Statements: Statement[];
    }
    export interface BlockAction {
      CustomResponse?: CustomResponse;
    }
    export interface Body {
      OversizeHandling?: string;
    }
    export interface ByteMatchStatement {
      FieldToMatch: FieldToMatch;
      PositionalConstraint: string;
      SearchString?: string;
      SearchStringBase64?: string;
      TextTransformations: TextTransformation[];
    }
    export interface CaptchaAction {
      CustomRequestHandling?: CustomRequestHandling;
    }
    export interface CaptchaConfig {
      ImmunityTimeProperty?: ImmunityTimeProperty;
    }
    export interface ChallengeAction {
      CustomRequestHandling?: CustomRequestHandling;
    }
    export interface ChallengeConfig {
      ImmunityTimeProperty?: ImmunityTimeProperty;
    }
    export interface CookieMatchPattern {
      All?: any;
      ExcludedCookies?: string[];
      IncludedCookies?: string[];
    }
    export interface Cookies {
      MatchPattern: CookieMatchPattern;
      MatchScope: string;
      OversizeHandling: string;
    }
    export interface CountAction {
      CustomRequestHandling?: CustomRequestHandling;
    }
    export interface CustomHTTPHeader {
      Name: string;
      Value: string;
    }
    export interface CustomRequestHandling {
      InsertHeaders: CustomHTTPHeader[];
    }
    export interface CustomResponse {
      CustomResponseBodyKey?: string;
      ResponseCode: number;
      ResponseHeaders?: CustomHTTPHeader[];
    }
    export interface CustomResponseBody {
      Content: string;
      ContentType: string;
    }
    export interface DefaultAction {
      Allow?: AllowAction;
      Block?: BlockAction;
    }
    export interface ExcludedRule {
      Name: string;
    }
    export interface FieldIdentifier {
      Identifier: string;
    }
    export interface FieldToMatch {
      AllQueryArguments?: any;
      Body?: Body;
      Cookies?: Cookies;
      Headers?: Headers;
      JsonBody?: JsonBody;
      Method?: any;
      QueryString?: any;
      SingleHeader?: any;
      SingleQueryArgument?: any;
      UriPath?: any;
    }
    export interface ForwardedIPConfiguration {
      FallbackBehavior: string;
      HeaderName: string;
    }
    export interface GeoMatchStatement {
      CountryCodes?: string[];
      ForwardedIPConfig?: ForwardedIPConfiguration;
    }
    export interface HeaderMatchPattern {
      All?: any;
      ExcludedHeaders?: string[];
      IncludedHeaders?: string[];
    }
    export interface Headers {
      MatchPattern: HeaderMatchPattern;
      MatchScope: string;
      OversizeHandling: string;
    }
    export interface IPSetForwardedIPConfiguration {
      FallbackBehavior: string;
      HeaderName: string;
      Position: string;
    }
    export interface IPSetReferenceStatement {
      Arn: string;
      IPSetForwardedIPConfig?: IPSetForwardedIPConfiguration;
    }
    export interface ImmunityTimeProperty {
      ImmunityTime: number;
    }
    export interface JsonBody {
      InvalidFallbackBehavior?: string;
      MatchPattern: JsonMatchPattern;
      MatchScope: string;
      OversizeHandling?: string;
    }
    export interface JsonMatchPattern {
      All?: any;
      IncludedPaths?: string[];
    }
    export interface Label {
      Name: string;
    }
    export interface LabelMatchStatement {
      Key: string;
      Scope: string;
    }
    export interface ManagedRuleGroupConfig {
      AWSManagedRulesBotControlRuleSet?: AWSManagedRulesBotControlRuleSet;
      LoginPath?: string;
      PasswordField?: FieldIdentifier;
      PayloadType?: string;
      UsernameField?: FieldIdentifier;
    }
    export interface ManagedRuleGroupStatement {
      ExcludedRules?: ExcludedRule[];
      ManagedRuleGroupConfigs?: ManagedRuleGroupConfig[];
      Name: string;
      RuleActionOverrides?: RuleActionOverride[];
      ScopeDownStatement?: Statement;
      VendorName: string;
      Version?: string;
    }
    export interface NotStatement {
      Statement: Statement;
    }
    export interface OrStatement {
      Statements: Statement[];
    }
    export interface OverrideAction {
      Count?: any;
      None?: any;
    }
    export interface RateBasedStatement {
      AggregateKeyType: string;
      ForwardedIPConfig?: ForwardedIPConfiguration;
      Limit: number;
      ScopeDownStatement?: Statement;
    }
    export interface RegexMatchStatement {
      FieldToMatch: FieldToMatch;
      RegexString: string;
      TextTransformations: TextTransformation[];
    }
    export interface RegexPatternSetReferenceStatement {
      Arn: string;
      FieldToMatch: FieldToMatch;
      TextTransformations: TextTransformation[];
    }
    export interface Rule {
      Action?: RuleAction;
      CaptchaConfig?: CaptchaConfig;
      ChallengeConfig?: ChallengeConfig;
      Name: string;
      OverrideAction?: OverrideAction;
      Priority: number;
      RuleLabels?: Label[];
      Statement: Statement;
      VisibilityConfig: VisibilityConfig;
    }
    export interface RuleAction {
      Allow?: AllowAction;
      Block?: BlockAction;
      Captcha?: CaptchaAction;
      Challenge?: ChallengeAction;
      Count?: CountAction;
    }
    export interface RuleActionOverride {
      ActionToUse: RuleAction;
      Name: string;
    }
    export interface RuleGroupReferenceStatement {
      Arn: string;
      ExcludedRules?: ExcludedRule[];
      RuleActionOverrides?: RuleActionOverride[];
    }
    export interface SingleHeader {
      Name: string;
    }
    export interface SingleQueryArgument {
      Name: string;
    }
    export interface SizeConstraintStatement {
      ComparisonOperator: string;
      FieldToMatch: FieldToMatch;
      Size: number;
      TextTransformations: TextTransformation[];
    }
    export interface SqliMatchStatement {
      FieldToMatch: FieldToMatch;
      SensitivityLevel?: string;
      TextTransformations: TextTransformation[];
    }
    export interface Statement {
      AndStatement?: AndStatement;
      ByteMatchStatement?: ByteMatchStatement;
      GeoMatchStatement?: GeoMatchStatement;
      IPSetReferenceStatement?: IPSetReferenceStatement;
      LabelMatchStatement?: LabelMatchStatement;
      ManagedRuleGroupStatement?: ManagedRuleGroupStatement;
      NotStatement?: NotStatement;
      OrStatement?: OrStatement;
      RateBasedStatement?: RateBasedStatement;
      RegexMatchStatement?: RegexMatchStatement;
      RegexPatternSetReferenceStatement?: RegexPatternSetReferenceStatement;
      RuleGroupReferenceStatement?: RuleGroupReferenceStatement;
      SizeConstraintStatement?: SizeConstraintStatement;
      SqliMatchStatement?: SqliMatchStatement;
      XssMatchStatement?: XssMatchStatement;
    }
    export interface TextTransformation {
      Priority: number;
      Type: string;
    }
    export interface VisibilityConfig {
      CloudWatchMetricsEnabled: boolean;
      MetricName: string;
      SampledRequestsEnabled: boolean;
    }
    export interface XssMatchStatement {
      FieldToMatch: FieldToMatch;
      TextTransformations: TextTransformation[];
    }
  }
  export interface WebACLAssociation {
    ResourceArn: string;
    WebACLArn: string;
  }
}
export namespace Wisdom {
  export interface Assistant {
    Description?: string;
    Name: string;
    ServerSideEncryptionConfiguration?: Assistant.ServerSideEncryptionConfiguration;
    Tags?: Tag[];
    Type: string;
  }
  export namespace Assistant {
    export interface Attr {
      AssistantArn: string;
      AssistantId: string;
    }
    export interface ServerSideEncryptionConfiguration {
      KmsKeyId?: string;
    }
  }
  export interface AssistantAssociation {
    AssistantId: string;
    Association: AssistantAssociation.AssociationData;
    AssociationType: string;
    Tags?: Tag[];
  }
  export namespace AssistantAssociation {
    export interface Attr {
      AssistantArn: string;
      AssistantAssociationArn: string;
      AssistantAssociationId: string;
    }
    export interface AssociationData {
      KnowledgeBaseId: string;
    }
  }
  export interface KnowledgeBase {
    Description?: string;
    KnowledgeBaseType: string;
    Name: string;
    RenderingConfiguration?: KnowledgeBase.RenderingConfiguration;
    ServerSideEncryptionConfiguration?: KnowledgeBase.ServerSideEncryptionConfiguration;
    SourceConfiguration?: KnowledgeBase.SourceConfiguration;
    Tags?: Tag[];
  }
  export namespace KnowledgeBase {
    export interface Attr {
      KnowledgeBaseArn: string;
      KnowledgeBaseId: string;
    }
    export interface AppIntegrationsConfiguration {
      AppIntegrationArn: string;
      ObjectFields: string[];
    }
    export interface RenderingConfiguration {
      TemplateUri?: string;
    }
    export interface ServerSideEncryptionConfiguration {
      KmsKeyId?: string;
    }
    export interface SourceConfiguration {
      AppIntegrations: AppIntegrationsConfiguration;
    }
  }
}
export namespace WorkSpaces {
  export interface ConnectionAlias {
    ConnectionString: string;
    Tags?: Tag[];
  }
  export namespace ConnectionAlias {
    export interface Attr {
      AliasId: string;
      Associations: ConnectionAliasAssociation[];
      ConnectionAliasState: string;
    }
    export interface ConnectionAliasAssociation {
      AssociatedAccountId?: string;
      AssociationStatus?: string;
      ConnectionIdentifier?: string;
      ResourceId?: string;
    }
  }
  export interface Workspace {
    BundleId: string;
    DirectoryId: string;
    RootVolumeEncryptionEnabled?: boolean;
    Tags?: Tag[];
    UserName: string;
    UserVolumeEncryptionEnabled?: boolean;
    VolumeEncryptionKey?: string;
    WorkspaceProperties?: Workspace.WorkspaceProperties;
  }
  export namespace Workspace {
    export interface Attr {}
    export interface WorkspaceProperties {
      ComputeTypeName?: string;
      RootVolumeSizeGib?: number;
      RunningMode?: string;
      RunningModeAutoStopTimeoutInMinutes?: number;
      UserVolumeSizeGib?: number;
    }
  }
}
export namespace XRay {
  export interface Group {
    FilterExpression?: string;
    GroupName?: string;
    InsightsConfiguration?: Group.InsightsConfiguration;
    Tags?: any[];
  }
  export namespace Group {
    export interface Attr {
      GroupARN: string;
    }
    export interface InsightsConfiguration {
      InsightsEnabled?: boolean;
      NotificationsEnabled?: boolean;
    }
    export interface TagsItems {
      Key: string;
      Value: string;
    }
  }
  export interface ResourcePolicy {
    BypassPolicyLockoutCheck?: boolean;
    PolicyDocument: string;
    PolicyName: string;
  }
  export interface SamplingRule {
    RuleName?: string;
    SamplingRule?: SamplingRule.SamplingRule;
    SamplingRuleRecord?: SamplingRule.SamplingRuleRecord;
    SamplingRuleUpdate?: SamplingRule.SamplingRuleUpdate;
    Tags?: any[];
  }
  export namespace SamplingRule {
    export interface Attr {
      RuleARN: string;
    }
    export interface SamplingRule {
      Attributes?: Record<string, string>;
      FixedRate?: number;
      HTTPMethod?: string;
      Host?: string;
      Priority?: number;
      ReservoirSize?: number;
      ResourceARN?: string;
      RuleARN?: string;
      RuleName?: string;
      ServiceName?: string;
      ServiceType?: string;
      URLPath?: string;
      Version?: number;
    }
    export interface SamplingRuleRecord {
      CreatedAt?: string;
      ModifiedAt?: string;
      SamplingRule?: SamplingRule;
    }
    export interface SamplingRuleUpdate {
      Attributes?: Record<string, string>;
      FixedRate?: number;
      HTTPMethod?: string;
      Host?: string;
      Priority?: number;
      ReservoirSize?: number;
      ResourceARN?: string;
      RuleARN?: string;
      RuleName?: string;
      ServiceName?: string;
      ServiceType?: string;
      URLPath?: string;
    }
    export interface TagsItems {
      Key: string;
      Value: string;
    }
  }
}
export namespace ASK {
  export interface Skill {
    AuthenticationConfiguration: Skill.AuthenticationConfiguration;
    SkillPackage: Skill.SkillPackage;
    VendorId: string;
  }
  export namespace Skill {
    export interface Attr {}
    export interface AuthenticationConfiguration {
      ClientId: string;
      ClientSecret: string;
      RefreshToken: string;
    }
    export interface Overrides {
      Manifest?: any;
    }
    export interface SkillPackage {
      Overrides?: Overrides;
      S3Bucket: string;
      S3BucketRole?: string;
      S3Key: string;
      S3ObjectVersion?: string;
    }
  }
}
