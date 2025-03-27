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
import java.util.zip.GZIPInputStream;
import java.util.Arrays;
import java.io.ByteArrayInputStream;
import java.io.BufferedInputStream;

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


            Boolean fileList = loadStructure(responseBody);
            
            textArea.setCaretPosition(0);
            this.expandCheckBox.setSelected(true);

        }

        private static boolean isGzipped(byte[] data) {
            return data.length >= 2 && (data[0] == (byte) 0x1F) && (data[1] == (byte) 0x8B);
        }

        private static boolean isZip(byte[] data) {
            return data.length >= 4 &&
                (data[0] == (byte) 0x50) &&
                (data[1] == (byte) 0x4B) &&
                (data[2] == (byte) 0x03) &&
                (data[3] == (byte) 0x04);
        }

        private void setPlaceholder(JTextField textField, String placeholderText) {
            textField.setText(placeholderText);
            textField.setForeground(Color.GRAY);
        }
        private Boolean loadStructure(byte[] data) {
            if (isGzipped(data)) {
                return loadTarGzStructure(data);
            }else if (isZip(data)){
                return loadZipStructure(data);
            }
            return false;
        }


        
        private Boolean loadTarGzStructure(byte[] gzData){

            String longName = null;
            try{

                ByteArrayInputStream byteStream = new ByteArrayInputStream(gzData);
                GZIPInputStream tarInputStream = new GZIPInputStream(byteStream);
                BufferedInputStream tarInput = new BufferedInputStream(tarInputStream);
                
                this.root.removeAllChildren();
            

                byte[] header = new byte[512];

                while (tarInput.read(header) == 512) {
                    String name = extractFullName(header);
                    char typeFlag = (char) header[156];
                    long size = extractSize(header);

                    if (name.isEmpty()) break;

                    if ("././@LongLink".equals(name)) {
                        byte[] nameBytes = new byte[(int) size];
                        int read = tarInput.read(nameBytes);
                        if (read != size) throw new IOException("Incomplete LongLink read");

                        longName = new String(nameBytes, 0, read).split("\0")[0];

                        long skip = (512 - (size % 512)) % 512;
                        while (skip > 0) {
                            long s = tarInput.skip(skip);
                            if (s <= 0) break;
                            skip -= s;
                        }

                        tarInput.mark(512);
                        byte[] nextHeader = new byte[512];
                        if (tarInput.read(nextHeader) != 512) break;
                        char nextType = (char) nextHeader[156];
                        boolean isRealEntry = nextHeader[0] != 0 &&
                            (nextType == '0' || nextType == '\0' || nextType == '5');

                        if (isRealEntry) {
                            name = extractFullName(nextHeader);
                            if (longName != null) name = longName;
                            System.out.println(name);

                            long nextSize = extractSize(nextHeader);
                            long skipNext = nextSize + (512 - (nextSize % 512)) % 512;
                            while (skipNext > 0) {
                                long s = tarInput.skip(skipNext);
                                if (s <= 0) break;
                                skipNext -= s;
                            }
                            longName = null;
                        } else {
                            longName = null;
                        }

                        continue;
                    }

                    if (longName != null) {
                        name = longName;
                        longName = null;
                    }

                    addPathToTree(name);

                   long skip = size + (512 - (size % 512)) % 512;
                    while (skip > 0) {
                        long s = tarInput.skip(skip);
                        if (s <= 0) break;
                        skip -= s;
                    }
                }

                this.treeModel.nodeStructureChanged(this.root);
                treeModel.reload();
                SwingUtilities.invokeLater(() -> expandAll(tree, new TreePath(root)));

            }catch (java.io.IOException e){
                return false;
            }
            
            return false;
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


        private static String extractFullName(byte[] header) {
            String name = extractString(header, 0, 100);
            String prefix = extractString(header, 345, 155);
            if (!prefix.isEmpty()) {
                name = prefix + "/" + name;
            }
            return name;
        }

        private static String extractString(byte[] buf, int offset, int length) {
            StringBuilder sb = new StringBuilder();
            for (int i = offset; i < offset + length && buf[i] != 0; i++) {
                sb.append((char) buf[i]);
            }
            return sb.toString();
        }

        private static long extractSize(byte[] header) {
            long size = 0;
            for (int i = 124; i < 124 + 12 && header[i] != 0; i++) {
                if (header[i] >= '0' && header[i] <= '7') {
                    size = (size << 3) + (header[i] - '0');
                }
            }
            return size;
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
