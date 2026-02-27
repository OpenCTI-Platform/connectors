import os
from typing import Self

import yaml
from pycti import get_config_variable

config_file_path: str = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'

config: dict = (
    yaml.load(open(config_file_path), Loader=yaml.FullLoader)
    if os.path.isfile(config_file_path)
    else {}
)

class Config:
    """ Base configuration class """
    _base_params = (
        'env_locale', 
        'opt_network_connect',
        'opt_network_fakenet',
        'opt_network_tor',
        'opt_network_geo',
        'opt_network_mitm',
        'opt_network_residential_proxy',
        'opt_network_residential_proxy_geo',
        'opt_privacy_type',
        'obj_ext_extension'
    )

    VERSION = 'OpenCTI:6.7.4'

    def __init__(self, params: dict[str, bool | int | None | str]) -> None:
        self._params = params
        self._create_base_config()

        self.env_os: str = params.pop('env_os')
        self.anyrun_token = f"API-KEY {get_config_variable('ANYRUN_API_KEY', ['anyrun', 'token'], config)}"
        self.enable_ioc = get_config_variable('ANYRUN_ENABLE_IOC', ['anyrun', 'enable_ioc'], config)


    def _create_base_config(self) -> dict[str, bool | int | None | str]:
        """
        Generates a dictionary using content of docker-compose.yml or config.yml file

        :return: Dictionary with base user settings
        """
        for param_name in Config._base_params:
            self._params[param_name] = get_config_variable(
                f'ANYRUN_{param_name.upper()}',
                [f'anyrun_{param_name[:3]}', param_name],
                config
            )
       
        self._params['opt_timeout'] = get_config_variable(
            'ANYRUN_OPT_TIMEOUT',
            ['anyrun_opt', 'opt_timeout'],
            config,
            isNumber=True
        )

        return self._params

    @classmethod
    def update_config(cls, submission_obj: str | tuple[bytes, str], entity_type: str) -> Self:
        """
        Update config parameters using user environment settings

        :param submission_obj: OpenCTI entity object
        :param entity_type: OpenCTI entity type
        :return: New Config instance for the specified environment
        :raises ValueError: If invalid **os_type** option value is specified
        """
        os_type = get_config_variable(
            'ANYRUN_OS_TYPE',
            ['anyrun_env', 'os_type'],
            config
        )

        if os_type == 'windows':
            return cls(cls._create_windows_config(submission_obj, entity_type))

        if os_type == 'linux':
            return cls(cls._create_linux_config(submission_obj, entity_type))

        if os_type == 'android':
            return cls(cls._create_android_config(submission_obj, entity_type))

        raise ValueError(f'Unspecified submission os: {os_type}' if os_type else 'The os_type option must be specified')

    @staticmethod
    def _create_windows_config(
            submission_obj: str | tuple[bytes, str],
            entity_type: str
    ) -> dict[str, bool | int | None | str]:
        """
        Updates config using Windows environment settings

        :param submission_obj: OpenCTI entity object
        :param entity_type: OpenCTI entity type
        :return: New Config instance for the Windows environment
        """
        params = dict()
        params['env_os'] = 'windows'

        params['env_version'] = get_config_variable(
            'ANYRUN_ENV_VERSION',
            ['anyrun_windows_env', 'env_version'],
            config
        )

        params['env_bitness'] = get_config_variable(
            'ANYRUN_ENV_BITNESS',
            ['anyrun_windows_env', 'env_bitness'],
            config,
            isNumber=True
        )

        params['env_type'] = get_config_variable(
            'ANYRUN_ENV_TYPE',
            ['anyrun_windows_env', 'env_type'],
            config
        )
        
        if entity_type == 'File':
            params['file_content'] = submission_obj[0]
            params['filename'] = submission_obj[1]

            params['obj_ext_startfolder'] = get_config_variable(
                'ANYRUN_OBJ_EXT_STARTFOLDER',
                ['anyrun_windows_env', 'obj_ext_startfolder'],
                config
            )

            params['obj_ext_cmd'] = get_config_variable(
                'ANYRUN_OBJ_EXT_CMD',
                ['anyrun_windows_env', 'obj_ext_cmd'],
                config
            )

            params['obj_force_elevation'] = get_config_variable(
                'ANYRUN_OBJ_FORCE_ELEVATION',
                ['anyrun_windows_env', 'obj_force_elevation'],
                config
            )

        if entity_type == 'Url':
           params = Config._process_url(params, submission_obj)

        return params

    @staticmethod
    def _create_linux_config(
            submission_obj: str | tuple[bytes, str],
            entity_type: str
    ) -> dict[str, bool | int | None | str]:
        """
        Updates config using Linux environment settings

        :param submission_obj: OpenCTI entity object
        :param entity_type: OpenCTI entity type
        :return: New Config instance for the Linux environment
        """
        params = dict()
        params['env_os'] = 'linux'

        if entity_type == 'File':
            params['file_content'] = submission_obj[0]
            params['filename'] = submission_obj[1]

            params['obj_ext_startfolder'] = get_config_variable(
                'ANYRUN_OBJ_EXT_STARTFOLDER',
                ['anyrun_linux_env', 'obj_ext_startfolder'],
                config
            )

            params['obj_ext_cmd'] = get_config_variable(
                'ANYRUN_OBJ_EXT_CMD',
                ['anyrun_linux_env', 'obj_ext_cmd'],
                config
            )

            params['run_as_root'] = get_config_variable(
                'ANYRUN_RUN_AS_ROOT',
                ['anyrun_linux_env', 'run_as_root'],
                config
            )

        if entity_type == 'Url':
            params = Config._process_url(params, submission_obj)

        return params

    @staticmethod
    def _create_android_config(
            submission_obj: str | tuple[bytes, str],
            entity_type: str
    ) -> dict[str, bool | int | None | str]:
        """
        Updates config using Android environment settings

        :param submission_obj: OpenCTI entity object
        :param entity_type: OpenCTI entity type
        :return: New Config instance for the Android environment
        """
        params = dict()
        params['env_os'] = 'android'

        if entity_type == 'File':
            params['file_content'] = submission_obj[0]
            params['filename'] = submission_obj[1]

            params['obj_ext_cmd'] = get_config_variable(
                'ANYRUN_OBJ_EXT_CMD',
                ['anyrun_android_env', 'obj_ext_cmd'],
                config
            )

        if entity_type == 'Url':
            params = Config._process_url(params, submission_obj)

        return params

    @staticmethod
    def _process_url(
            params: dict[str, bool | int | None | str],
            submission_obj: str
    ) -> dict[str, bool | int | None | str]:
        """
        Updates config using Url environment settings

        :param params: Config parameters
        :param submission_obj: OpenCTI entity object
        :return: Updated config
        """
        params['obj_url'] = submission_obj

        params['obj_ext_browser'] = get_config_variable(
            'ANYRUN_OBJ_EXT_BROWSER',
            ['anyrun_env', 'obj_ext_browser'],
            config
        )

        return params

    @property
    def to_dict(self) -> dict[str, bool | int | None | str]:
        return self._params
