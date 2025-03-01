import burp.*;
import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.*;
import java.util.*;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;
import java.util.Comparator;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import javax.swing.tree.*;

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

    private class DecompressTab implements IMessageEditorTab {
        private final JPanel panel;
        private final JTextArea textArea;
        private byte[] currentMessage;
        private final IExtensionHelpers helpers;
        private final JButton saveButton;
        private StringBuilder output;
        private DefaultMutableTreeNode root;
        private DefaultTreeModel treeModel;
        private JTree tree;
        private JCheckBox expandCheckBox;

        private final String placeholder = "Search as you type...";


        public DecompressTab(IMessageEditorController controller, boolean editable, IExtensionHelpers helpers) {
            this.helpers = helpers;
            this.panel = new JPanel(new BorderLayout());
            this.textArea = new JTextArea();
            this.textArea.setFont(new Font(Font.MONOSPACED, Font.BOLD, 14));
            this.textArea.setEditable(false);
            this.root = new DefaultMutableTreeNode("Root");
            this.treeModel = new DefaultTreeModel(root);
            this.tree = new JTree(treeModel);
            this.tree.setShowsRootHandles(true);
            this.tree.setRootVisible(true);
            this.tree.setShowsRootHandles(true);
            this.panel.add(new JScrollPane(this.tree));


            JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
            saveButton = new JButton("Save File");
            saveButton.addActionListener(e -> saveToFile());

            toolbar.add(saveButton);
            this.panel.add(toolbar, BorderLayout.SOUTH);

            this.expandCheckBox = new JCheckBox("Fold/Unfold");
            this.expandCheckBox.addActionListener(e -> toggleTreeExpansion(this.expandCheckBox.isSelected()));
            toolbar.add(expandCheckBox);
            
            JTextField textField = new JTextField(20);
            toolbar.add(textField);

            textField.getDocument().addDocumentListener(new DocumentListener() {
                @Override
                public void insertUpdate(DocumentEvent e) {
                    filterTree(textField.getText());
                }

                @Override
                public void removeUpdate(DocumentEvent e) {
                    filterTree(textField.getText());
                }

                @Override
                public void changedUpdate(DocumentEvent e) {
                    filterTree(textField.getText());
                }

                private void updateValue() {

                    filterTree(textField.getText());
                }
            });

            textField.addFocusListener(new FocusListener() {
                @Override
                public void focusGained(FocusEvent e) {
                    if (textField.getText().equals(placeholder)) {
                        textField.setText("");
                        textField.setForeground(Color.BLACK);
                    }
                }

                @Override
                public void focusLost(FocusEvent e) {
                    if (textField.getText().isEmpty()) {
                        setPlaceholder(textField, placeholder);
                    }
                }
            });

            setPlaceholder(textField, placeholder);
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
            Boolean fileList = loadZipStructure(responseBody);
            if (fileList) {
                textArea.setText("Here's the file list\n\n" + this.output.toString());
            } else {
                textArea.setText("Response Body:\nIl file NON e' compresso");
            }
            textArea.setCaretPosition(0);
            this.expandCheckBox.setSelected(true);

        }

        private void setPlaceholder(JTextField textField, String placeholderText) {
            textField.setText(placeholderText);
            textField.setForeground(Color.GRAY);
        }
        private Boolean loadZipStructure(byte[] zipData) {
            StringBuilder fileList = new StringBuilder();
            this.root.removeAllChildren();
            java.util.Map<String, Boolean> fileMap = new java.util.TreeMap<>();
            try (java.util.zip.ZipInputStream zipStream = new java.util.zip.ZipInputStream(new java.io.ByteArrayInputStream(zipData))) {
                ZipEntry entry = null;
                while ((entry = zipStream.getNextEntry()) != null) {
                    addPathToTree(entry.getName());
                }
                this.treeModel.nodeStructureChanged(this.root);
                treeModel.reload();
                SwingUtilities.invokeLater(() -> expandAll(tree, new TreePath(root)));
            } catch (java.io.IOException e) {
                return false;
            }
            return true;
        }


        private void expandAll(JTree tree, TreePath parent) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) parent.getLastPathComponent();
            for (int i = 0; i < node.getChildCount(); i++) {
                DefaultMutableTreeNode childNode = (DefaultMutableTreeNode) node.getChildAt(i);
                TreePath path = parent.pathByAddingChild(childNode);
                expandAll(tree, path);
            }
            tree.expandPath(parent);
        }


        private void collapseAll(JTree tree, TreePath parent) {
            DefaultMutableTreeNode node = (DefaultMutableTreeNode) parent.getLastPathComponent();
            for (int i = 0; i < node.getChildCount(); i++) {
                DefaultMutableTreeNode childNode = (DefaultMutableTreeNode) node.getChildAt(i);
                TreePath path = parent.pathByAddingChild(childNode);
                collapseAll(tree, path);
            }
            tree.collapsePath(parent);
        }

        private void toggleTreeExpansion(boolean expand) {
            if (expand) {
                expandAll(this.tree, new TreePath(this.root));
            } else {
                collapseAll(this.tree, new TreePath(this.root));
            }
        }


        private void addPathToTree(String path) {
            String[] parts = path.split("/");
            DefaultMutableTreeNode currentNode = this.root;

            for (String part : parts) {
                if (part.isEmpty()) continue;
                boolean found = false;
                for (int i = 0; i < currentNode.getChildCount(); i++) {
                    DefaultMutableTreeNode child = (DefaultMutableTreeNode) currentNode.getChildAt(i);
                    if (child.getUserObject().equals(part)) {
                        currentNode = child;
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    DefaultMutableTreeNode newNode = new DefaultMutableTreeNode(part);
                    currentNode.add(newNode);
                    currentNode = newNode;
                }
            }
        }

        private void printTree(TreeNode node, String prefix, boolean isLast) {
            if (!node.name.isEmpty()) {
                this.output.append(prefix + (isLast ? "└─ " : "├─ ") + node.name + "\n");
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


        private void filterTree(String query) {
            if (query.isEmpty() || query.equals(placeholder)) {
                treeModel.setRoot(this.root);
                toggleTreeExpansion(expandCheckBox.isSelected());
                return;
            }
            DefaultMutableTreeNode filteredRoot = new DefaultMutableTreeNode("Filtered Root");
            filterNodes(this.root, filteredRoot, query.toLowerCase());
            treeModel.setRoot(filteredRoot);
            SwingUtilities.invokeLater(() -> expandAll(tree, new TreePath(filteredRoot)));
        }

        private boolean filterNodes(DefaultMutableTreeNode original, DefaultMutableTreeNode filtered, String query) {
            boolean hasMatch = original.getUserObject().toString().toLowerCase().contains(query);
            for (int i = 0; i < original.getChildCount(); i++) {
                DefaultMutableTreeNode childNode = (DefaultMutableTreeNode) original.getChildAt(i);
                DefaultMutableTreeNode filteredChild = new DefaultMutableTreeNode(childNode.getUserObject());
                if (filterNodes(childNode, filteredChild, query)) {
                    filtered.add(filteredChild);
                    hasMatch = true;
                }
            }
            return hasMatch;
        }

    }
}
