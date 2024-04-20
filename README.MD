<a name="readme-top"></a>


<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/AliceGrey/ferromagnet">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">FerroMagnet</h3>

  <p align="center">
    An Automated Threat Actor Infrastructure Tracking Tool
</div>


<!-- ABOUT THE PROJECT -->
## About The Project

Cyber Threat Intelligence (CTI) plays a pivotal role in countering malicious activities by systematically collecting, analyzing, and disseminating information on cyber threats. CTI analysts track and monitor threat actors who engage in various malicious activities, including network intrusion and cyber warfare (Johnson et al., 2016). Understanding the dynamic nature of threat actor infrastructure is crucial for effectively detecting and mitigating cyber threats (Nakamura & Åström, 2021). This paper proposes an automated threat actor infrastructure tracking tool named FerroMagnet, which aims to streamline the identification and analysis of threat actor infrastructure. Utilizing Python3 and existing libraries for internet scanning tools, FerroMagnet leverages commercial internet scanning services such as Shodan and Censys to gather data on command and control (C2) servers. The primary focus of FerroMagnet is to detect and analyze Cobalt Strike beacons, a prevalent C2 implant utilized by threat actors. By extracting configuration data from these beacons, including communication protocols and payloads, FerroMagnet enhances the understanding of threat actors' Tactics, Techniques, and Procedures (TTPs), enabling better defense preparedness (Clark & Barros, 2020). Additionally, FerroMagnet aims to expand its support to encompass other command and control systems, enhancing its versatility and utility. The success of FerroMagnet relies on internet scanning data available via Shodan and Censys APIs. This paper outlines the expected data types, transformations, and functions employed by FerroMagnet to achieve its objectives, ultimately contributing to the enhancement of cyber threat intelligence analysis.

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- GETTING STARTED -->
## Getting Started

To get a local copy up and running follow these simple example steps.

### Prerequisites

1. You need to install the required python libraries ``censys``, ``shodan``, and ``xmltodict``.
    ```sh
    pip install -r requirements.txt
    ```

2. You will need to acquire a [Shodan](https://account.shodan.io/register) and [Censys](https://accounts.censys.io/register) API key to run the program without the debug mode enabled.

3. This tool actively scans threat actor infrastructure, **please make sure you are running it from an IP that isn't attributable to you**. I recommend using the [mullvad](https://mullvad.net/en) vpn service.

### Configuration

_You must add your censys and shodan api keys to the config file_

1. Get your API Keys at [Shodan](https://account.shodan.io) and [Censys](https://accounts.censys.io).
2. Clone the repo
   ```sh
   git clone https://github.com/AliceGrey/ferromagnet.git
   ```
3. Rename the example config
   ```sh
   mv example-config.json config.json 
   ```
4. Enter your API keys in `config.json` (These are not real keys - they are examples)
   ```json
   "shodan": {
        "api_key": "ZjDv9QSQS16UQubWLTXtiefdwcccj8tk"
    },
    "censys": {
        "api_id": "43390132-1e20-4bzz-83e0-bc025577cad2",
        "api_secret": "aa9pj0imccZ916747qEWjhBJzqbQ2E8d"
    }
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- USAGE EXAMPLES -->
## Usage (Debug Mode)
To test the functionality of the program using pre-seeded Shodan and Censys data (if you don't have API keys): 
```sh
DEBUG=true python3 ferromagnet.py
```

## Usage (Regular Mode)
To run the full script and actively query Shodan and Censys:
```sh
python3 ferromagnet.py
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.MD` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

Projects I'd like to give credit to.

* [Original Grab Beacon Config Nmap Script](https://github.com/whickey-r7/grab_beacon_config)
* [Best-README-Template](https://github.com/othneildrew/Best-README-Template)

<p align="right">(<a href="#readme-top">back to top</a>)</p>
