// The connectors of OpenCTI, one component each, generated from the manifest that the repository
// of the connectors builds, manifest.json: their image, their title, their logo, and the settings
// their config schema declares. Each runs at the version of the OpenCTI platform's descriptor, and
// reaches the platform through its contract opencti, as a service account of its own; the
// platform gives it the queues of RabbitMQ when it registers.
//
// It reads the manifest of this worktree. The version comes from the descriptor of the platform,
// in the default worktree of the OpenCTI repository, beside this one in code/; without it, the
// connectors run their latest image.
//
// Answers XTM Studio, on its standard output: { schema: 1, inputs, components }.

import { access, readFile } from 'node:fs/promises';
import { join } from 'node:path';

/** This worktree, from this directory: <worktree>/.xtm-studio/components/opencti/connectors. */
const REPOSITORY = '../../../..';
const MANIFEST = join(REPOSITORY, 'manifest.json');
/** The descriptor of the platform, in the OpenCTI repository beside this one. */
const PLATFORM = '../../../../../opencti/.xtm-studio/components/opencti/platform/component.yaml';

interface Property {
  type?: string | string[];
  default?: unknown;
  const?: unknown;
  description?: string;
  format?: string;
  writeOnly?: boolean;
  deprecated?: boolean;
}

interface Contract {
  title: string;
  slug: string;
  short_description?: string;
  container_image: string;
  container_type: string;
  config_schema?: { properties?: Record<string, Property>; required?: string[] };
}

/** What every connector gets from XTM Studio, never set by hand. */
const GIVEN = new Set(['OPENCTI_URL', 'OPENCTI_TOKEN', 'CONNECTOR_ID', 'CONNECTOR_TYPE', 'CONNECTOR_NAME', 'CONNECTOR_SCOPE']);

/** A value of a schema, as a variable holds it: a list joined with commas. */
const valueOf = (value: unknown): string => (Array.isArray(value) ? value.join(',') : String(value));

/** Whether a setting is a secret: its schema says so, or its name does. */
const isSecret = (name: string, property: Property) =>
  property.format === 'password' || property.writeOnly === true || /(PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|_KEY$|PRIVATE)/.test(name);

const exists = async (path: string) => {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
};

const platform = (await exists(PLATFORM)) ? await readFile(PLATFORM, 'utf8') : '';
const version = /^image:\s*\{\s*version:\s*([^\s}]+)\s*\}/m.exec(platform)?.[1] ?? 'latest';
const manifest = JSON.parse(await readFile(MANIFEST, 'utf8')) as { contracts: Contract[] };

const components = [];
for (const contract of manifest.contracts) {
  // opencti/connector-<directory>: the image, which names the directory; the slug may not.
  const name = contract.container_image;
  const directory = name.replace(/^opencti\/connector-/, '');
  const category = contract.container_type.toLowerCase().replace(/_/g, '-');
  const logos = ['png', 'jpg', 'svg'].map((ext) => join(REPOSITORY, category, directory, '__metadata__', `logo.${ext}`));
  const logo = (await Promise.all(logos.map(exists))).findIndex(Boolean);
  const properties = contract.config_schema?.properties ?? {};
  const required = new Set(contract.config_schema?.required ?? []);
  const fixed = (key: string) => properties[key]?.const ?? properties[key]?.default;
  const environment: Record<string, string> = {
    OPENCTI_URL: '{{requires.opencti.contract.url.protocol}}://{{requires.opencti.contract.url.address}}',
    OPENCTI_TOKEN: '{{requires.opencti.output.token}}',
    CONNECTOR_ID: '{{secrets.CONNECTOR_ID}}',
    CONNECTOR_TYPE: valueOf(fixed('CONNECTOR_TYPE') ?? contract.container_type),
    CONNECTOR_NAME: valueOf(fixed('CONNECTOR_NAME') ?? contract.title),
    CONNECTOR_LOG_LEVEL: 'info',
  };
  const scope = fixed('CONNECTOR_SCOPE');
  if (scope !== undefined) environment['CONNECTOR_SCOPE'] = valueOf(scope);
  const variables: Record<string, { description?: string; secret?: boolean; required?: boolean }> = {};
  for (const [key, property] of Object.entries(properties)) {
    if (GIVEN.has(key) || key in environment || property.deprecated) continue;
    variables[key] = {
      ...(property.description ? { description: property.description } : {}),
      ...(isSecret(key, property) ? { secret: true } : {}),
      ...(required.has(key) && property.default === undefined ? { required: true } : {}),
    };
  }
  // Without a schema, its scope is set by hand, as its README says.
  if (scope === undefined) variables['CONNECTOR_SCOPE'] = { description: 'What the connector handles, as its README says.', required: true };
  components.push({
    schema: 1,
    name,
    group: 'opencti-connectors',
    title: contract.title,
    description: `${contract.short_description ?? contract.title}${contract.config_schema ? '' : ' Its settings have no schema: see its README.'}`,
    ...(logo >= 0 ? { logo: logos[logo] } : { logo: { icon: 'box' } }),
    image: { version },
    secrets: { CONNECTOR_ID: { type: 'uuid' } },
    environment,
    variables,
    requires: { opencti: { count: '1', enrollment: { service_account: { name: '{{dataset.name}}' } } } },
  });
}

process.stdout.write(JSON.stringify({ schema: 1, inputs: [MANIFEST, PLATFORM], components }));
