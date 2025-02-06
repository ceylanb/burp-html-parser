package burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.FlowLayout;
import java.awt.Font;
import java.lang.StringBuilder;
import java.util.Arrays;
import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.BoxLayout;
import javax.swing.JPanel;
import javax.swing.JTextField;

// https://github.com/jhy/jsoup
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;


public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private static final Color colorError = new Color(247, 66, 62);
    private static final Color colorOK = new Color(81, 179, 100);
    private static final Color colorWarning = new Color(252, 151, 78);

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("HTML Content Extractor");
        
        // Log extension load
        callbacks.printOutput("HTML Content Extractor loaded successfully");

        // UI
        callbacks.registerMessageEditorTabFactory(BurpExtender.this);
    }

    class HTMLContentExtractorTab implements IMessageEditorTab {

        private ITextEditor outputArea;
        private JPanel container = new JPanel(new BorderLayout());
        private String input_html;
        private JTextField filtersBar;

        public HTMLContentExtractorTab(IMessageEditorController controller, boolean editable) {

            // Filters container
            JPanel filters = new JPanel();
            filters.setLayout(new BoxLayout(filters, BoxLayout.Y_AXIS));

            // Filters bar
            filtersBar = new JTextField();
            filtersBar.setBackground(colorWarning);
            filtersBar.setFont(new Font("monospaced", Font.BOLD, 13));
            filtersBar.setForeground(Color.WHITE);
            filtersBar.setToolTipText("Use @outer:, @inner:, or @attr:name: prefix (e.g., '@attr:href:a' for all link URLs)");
            Action action = new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    applyFilters();
                }
            };
            filtersBar.addActionListener(action);
            filtersBar.setFocusTraversalKeysEnabled(false);

            // Filters helpers
            JPanel filtersHelpers = new JPanel(new FlowLayout(FlowLayout.LEFT));

            // Assemble filters container
            filters.add(filtersBar);
            filters.add(filtersHelpers);

            // Output area
            outputArea = callbacks.createTextEditor();
            outputArea.setEditable(false);

            // Assemble main container
            container.add(filters, BorderLayout.NORTH);
            container.add(outputArea.getComponent(), BorderLayout.CENTER);
        }

        @Override
        public String getTabCaption() {
            return "HTML Content Extractor";
        }

        @Override
        public Component getUiComponent() {
            return container;
        }

        // Enable for HTML only
        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            try {
                if (content == null) return false;
                
                if (isRequest) {
                    IRequestInfo requestInfo = helpers.analyzeRequest(content);
                    // Check for HTML content type in headers
                    for (String header : requestInfo.getHeaders()) {
                        if (header.toLowerCase().startsWith("content-type: text/html")) {
                            return true;
                        }
                    }
                    return false;
                } else {
                    IResponseInfo responseInfo = helpers.analyzeResponse(content);
                    return responseInfo.getStatedMimeType().equals("HTML") || 
                           responseInfo.getInferredMimeType().equals("HTML");
                }
            } catch (Exception e) {
                callbacks.printError("Error in isEnabled: " + e.getMessage());
                return false;
            }
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            try {
                // Clear our display and reset input
                if (content == null) {
                    outputArea.setText(new byte[0]);
                    input_html = null;
                    return;
                }

                // Get HTML from response body
                int bodyOffset = 0;
                if (!isRequest) {
                    IResponseInfo responseInfo = helpers.analyzeResponse(content);
                    bodyOffset = responseInfo.getBodyOffset();
                }

                // Save HTML input
                try {
                    input_html = new String(Arrays.copyOfRange(content, bodyOffset, content.length));
                    filtersBar.setBackground(colorOK);
                    callbacks.printOutput("Successfully processed HTML content of length: " + input_html.length());
                } catch (Exception e) {
                    filtersBar.setBackground(colorError);
                    String errorMsg = "Error processing HTML content: " + e.getMessage();
                    outputArea.setText(errorMsg.getBytes());
                    callbacks.printError(errorMsg);
                }

                // Draw
                applyFilters();
            } catch (Exception e) {
                callbacks.printError("Error in setMessage: " + e.getMessage());
            }
        }


        public void applyFilters() {
            try {
                // Get the filter (CSS selector)
                String filters = filtersBar.getText().trim();
                boolean useOuterHtml = true; // default to outer
                String attributeName = null;

                // Check for output type prefix
                if (filters.startsWith("@inner:")) {
                    useOuterHtml = false;
                    filters = filters.substring(7);
                } else if (filters.startsWith("@outer:")) {
                    filters = filters.substring(7);
                } else if (filters.startsWith("@attr:")) {
                    int endIndex = filters.indexOf(":", 6);
                    if (endIndex != -1) {
                        attributeName = filters.substring(6, endIndex);
                        filters = filters.substring(endIndex + 1);
                    }
                }

                // Initialize output
                StringBuilder output = new StringBuilder();

                if (filters.isEmpty()) {
                    filters = "*";
                    callbacks.printOutput("Using default selector '*'");
                }

                // Parse the HTML
                Document document = Jsoup.parse(input_html);
                org.jsoup.select.Elements elements = document.select(filters);

                // Select elements based on filter and output type
                String filterResult;
                if (attributeName != null) {
                    // Join attribute values with newlines
                    filterResult = String.join("\n", elements.eachAttr(attributeName));
                } else {
                    filterResult = useOuterHtml ? elements.outerHtml() : elements.html();
                }

                // Append selected content to output
                if (!elements.isEmpty()) {
                    filtersBar.setBackground(colorOK);
                    output.append(filterResult);
                    
                    // Add element count for better feedback
                    int elementCount = elements.size();
                    String countMsg = "\n\nFound " + elementCount + " element(s)";
                    output.append(countMsg);
                    callbacks.printOutput("Successfully applied filter: " + filters + " - " + elementCount + " element(s) found");
                } else {
                    filtersBar.setBackground(colorError);
                    String msg = "No elements matched the selector: " + filters + "\n\nExample selectors:\n" +
                               "- @outer:input[type=hidden]  (hidden inputs with tags)\n" +
                               "- @inner:form               (form contents only)\n" +
                               "- @attr:href:a             (all link URLs)\n" +
                               "- @attr:value:input        (all input values)\n" +
                               "- @attr:class:div          (div class names)\n" +
                               "- input[type=text]          (default: outer HTML)";
                    output.append(msg);
                    callbacks.printOutput(msg);
                }

                // Set output area text
                outputArea.setText(output.toString().getBytes());
            } catch (Exception e) {
                String errorMsg = "Error applying filters: " + e.getMessage();
                outputArea.setText(errorMsg.getBytes());
                callbacks.printError(errorMsg);
                filtersBar.setBackground(colorError);
            }
        }

        @Override
        public byte[] getMessage() {
            return input_html.getBytes();
        }

        @Override
        public boolean isModified() {
            return false;
        }

        @Override
        public byte[] getSelectedData() {
            return outputArea.getSelectedText();
        }
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new HTMLContentExtractorTab(controller, editable);
    }
}
