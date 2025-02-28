import burp.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.*;
import java.util.*;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;
import java.util.Enumeration;
import java.util.Comparator;

public class BurpShowDecompressed implements IBurpExtender, IMessageEditorTabFactory {
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Decompress Tab");
        callbacks.registerMessageEditorTabFactory(this);
        callbacks.printOutput("Extension loaded successfully.");
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new DecompressTab(controller, editable, helpers);
    }

    private static class DecompressTab implements IMessageEditorTab {
        private final JPanel panel;
        private final JTextArea textArea;
        private byte[] currentMessage;
        private final IExtensionHelpers helpers;
        private final JButton saveButton;
        private StringBuilder output;

        public DecompressTab(IMessageEditorController controller, boolean editable, IExtensionHelpers helpers) {
            this.helpers = helpers;
            this.panel = new JPanel(new BorderLayout());
            
            this.textArea = new JTextArea();
            this.textArea.setFont(new Font(Font.MONOSPACED, Font.BOLD, 14));
            this.textArea.setEditable(false);
            this.panel.add(new JScrollPane(textArea), BorderLayout.CENTER);



            JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
            saveButton = new JButton("Save File");
            saveButton.addActionListener(e -> saveToFile());

            toolbar.add(saveButton);
            this.panel.add(toolbar, BorderLayout.SOUTH);

        }

        @Override
        public String getTabCaption() {
            return "Decompress";
        }

        @Override
        public Component getUiComponent() {
            return panel;
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            return !isRequest;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            if (content == null || isRequest) {
                textArea.setText("");
                return;
            }
            this.currentMessage = content;
            textArea.setText("");  


            IResponseInfo responseInfo = helpers.analyzeResponse(content);
            int bodyOffset = responseInfo.getBodyOffset();
            byte[] responseBody = java.util.Arrays.copyOfRange(content, bodyOffset, content.length);
            
            this.currentMessage = responseBody;
            
            this.output = new StringBuilder();
            Boolean fileList = listZipContents(responseBody);

            if(fileList){
                textArea.setText("Here's the file list\n\n"+this.output.toString());
            } else {
                textArea.setText("Response Body:\nIl file NON e' compresso");
            }

            textArea.setCaretPosition(0);
        }


        private Boolean listZipContents(byte[] zipData) {
            StringBuilder fileList = new StringBuilder();
            java.util.Map<String, Boolean> fileMap = new java.util.TreeMap<>();
            try (java.util.zip.ZipInputStream zipStream = new java.util.zip.ZipInputStream(new java.io.ByteArrayInputStream(zipData))) {
                
                TreeNode root = new TreeNode("");
                ZipEntry entry = null;
                while ( (entry = zipStream.getNextEntry()) != null ) {
                    addToTree(root, entry.getName());
                }
                printTree(root, "", true);

            } catch (java.io.IOException e) {
                return false;
            }
            return true;
        }
        
        private void addToTree(TreeNode root, String path) {
            String[] parts = path.split("/");
            TreeNode current = root;
            for (String part : parts) {
                    current = current.children.computeIfAbsent(part, k -> new TreeNode(part));
            }
        }

        private void printTree(TreeNode node, String prefix, boolean isLast) {
            if (!node.name.isEmpty()) {
                this.output.append( prefix + (isLast ? "└─ " : "├─ ") + node.name +"\n");
            }

            List<TreeNode> children = new ArrayList<>(node.children.values());
            children.sort(Comparator.comparing(n -> n.name));

            for (int i = 0; i < children.size(); i++) {
                String newPrefix = prefix + (isLast ? "   " : "│  ");
                printTree(children.get(i), newPrefix, i == children.size() - 1);
            }
        }

        private class TreeNode {
            String name;
            Map<String, TreeNode> children = new TreeMap<>();

            TreeNode(String name) {
                this.name = name;
            }
        }

        @Override
        public byte[] getMessage() {
            return currentMessage;
        }

        @Override
        public boolean isModified() {
            return false;
        }

        @Override
        public byte[] getSelectedData() {
            return textArea.getText().getBytes();
        }

        private void saveToFile() {
            JFileChooser fileChooser = new JFileChooser();
            int option = fileChooser.showSaveDialog(null);
            if (option == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                if (file.exists()) {
                    int overwriteOption = JOptionPane.showConfirmDialog(null, "File already exists. Overwrite?", "Confirm Overwrite", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                    if (overwriteOption != JOptionPane.YES_OPTION) {
                        return;
                    }
                }
                try (FileOutputStream fos = new FileOutputStream(file)) {
                    fos.write(currentMessage);
                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(null, "Error saving file: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        } 


    }
}
