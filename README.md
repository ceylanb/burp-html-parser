# HTML Content Extractor - Burp Suite Extension

This is a Burp Suite Extension that applies CSS selectors to extract and analyze specific parts of HTML content directly from the HTTP message viewer. With the power of CSS selectors, users can target elements, attributes, and nested structures in the HTML document, enabling precise and efficient content analysis during security assessments.

For a quick demonstration of how this extension works, check out the video below:

![Demo Video](img/demo.gif)

## Features

- Real-time HTML content extraction using CSS selectors
- Support for three extraction modes:
  - Complete elements (outer HTML)
  - Inner content only (inner HTML)
  - Specific attribute values
- Efficient analysis of potential security issues like XSS vectors and hidden fields
- Integration with Burp's HTTP message viewer for seamless workflow
- Element count and status feedback
- Powered by jsoup for reliable HTML parsing

## Usage

1. Load the extension in Burp Suite
2. Intercept HTTP traffic or browse through your proxy history
3. Select a response containing HTML content
4. Switch to the "HTML Content Extractor" tab
5. Enter your CSS selector with an optional prefix to control the output type:

### Selector Prefixes

- `@outer:` - Get complete elements with their tags (default if no prefix)
  ```
  @outer:input[type=hidden]  -> Shows complete hidden input tags
  @outer:form               -> Shows complete form elements
  ```

- `@inner:` - Get only the contents inside elements
  ```
  @inner:div.content       -> Shows only the content inside div
  @inner:form             -> Shows only the form contents
  ```

- `@attr:name:` - Get specific attribute values
  ```
  @attr:href:a           -> Gets all link URLs
  @attr:value:input      -> Gets all input values
  @attr:class:div        -> Gets all div class names
  @attr:src:img          -> Gets all image sources
  ```

### Example Selectors

- Find hidden inputs: `@outer:input[type=hidden]`
- Extract form contents: `@inner:form`
- Get all link URLs: `@attr:href:a`
- Find input values: `@attr:value:input[type=text]`
- Get class names: `@attr:class:div.content`

## Build

```bash
$ gradle fatJar
```

The extension will be built as a JAR file in `build/libs/html-content-extractor-all.jar`

## Requirements

- Burp Suite Professional or Community Edition (2023.1 or later)
- Java 8 or later

## Credits

HTML Content Extractor relies on the following libraries:

- [jsoup](https://jsoup.org/) - For HTML parsing and CSS selector support
- [Burp Extender API](https://portswigger.net/burp/extender) - For Burp Suite integration

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Inspired by

[Burp-JQ](https://github.com/synacktiv/burp-jq)
