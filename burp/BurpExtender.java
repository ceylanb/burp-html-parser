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

            IRequestInfo requestInfo;
            IResponseInfo responseInfo;

            if (isRequest) {
                requestInfo = helpers.analyzeRequest(content);
                return requestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_JSON;

            } else {
                responseInfo = helpers.analyzeResponse(content);
                return responseInfo.getStatedMimeType().equals("HTML") || responseInfo.getInferredMimeType().equals("HTML");
            }
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {

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

			} catch (Exception e) {
				filtersBar.setBackground(colorError);
				outputArea.setText(e.getMessage().getBytes());
			}

            // Draw
            applyFilters();
        }


        public void applyFilters() {
            // Get the filter (CSS selector)
            String filters = filtersBar.getText().trim();

            // Initialize output
            StringBuilder output = new StringBuilder();

            if (filters.isEmpty())
                filters = "*";

            // Parse the HTML
            Document document = Jsoup.parse(input_html);

            // Select elements based on filter
            String filterResult = document.select(filters).html();

            // Append selected content to output
            if (!filterResult.isEmpty()) {
                filtersBar.setBackground(colorOK); // Success color
                output.append(filterResult);
            } else {
                filtersBar.setBackground(colorError); // Error color if no match
                output.append("No elements matched the selector: ").append(filters);
            }

            // Set output area text
            outputArea.setText(output.toString().getBytes());
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
