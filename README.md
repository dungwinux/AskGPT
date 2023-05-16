# AskGPT

![Running AskGPT](images/screenshot.png)

## Prerequisites

-   Volatility3:
    -   Base: `git clone https://github.com/volatilityfoundation/volatility3`
    -   Windows symbol: See [volatility3/README.md](https://github.com/volatilityfoundation/volatility3#symbol-tables)
-   openai Python package
    -   Pip: `pip install openai`

## Running

Use `-p` option in Volatility3 to specify this directory. That way, the plugin
would be discovered.

```
python vol.py -p <AskGPT directory> -f <image> askgpt.AskGPT
```

Example:

```
python vol.py -p D:\git\AskGPT -f windows.mem.ram askgpt.AskGPT
```

You can also specify the model to use:

```
python vol.py -p D:\git\AskGPT --model-id gpt-3.5-turbo -f windows.mem.ram askgpt.AskGPT
```


## Screenshots

### Rensenware

![Scanning Windows 7 running Rensenware](images/rensenware2.png)
