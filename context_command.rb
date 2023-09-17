# Ruby requires
require 'java'
require 'json'
require 'pathname'
# Java imports
java_import javax.swing.JTabbedPane
java_import javax.swing.JFileChooser
java_import javax.swing.JPanel
java_import javax.swing.JTextArea
java_import javax.swing.JLabel
java_import javax.swing.JMenu             # Right-click Section menu
java_import javax.swing.JList             # Right-click Section menu
java_import javax.swing.JButton             # Right-click Section menu
java_import javax.swing.JMenuItem         # Right-click Regular menu
java_import java.awt.BorderLayout
java_import java.awt.Component
java_import javax.swing.JEditorPane
java_import javax.swing.JScrollPane
java_import javax.swing.ListSelectionModel
java_import java.awt.GridBagConstraints
java_import java.awt.GridBagLayout
java_import java.awt.GridLayout
java_import java.awt.Color
java_import java.awt.Dimension


# Burp Suite API imports
java_import 'burp.IBurpExtender'
java_import 'burp.IBurpExtenderCallbacks'
java_import 'burp.ITab'
java_import 'burp.IContextMenuFactory'


class BurpExtender
  include IBurpExtender
  include ITab
  include IContextMenuFactory
  attr_reader :callbacks
  $num_tabs = 0
  $divder = '---------------------------------------------------------------------------------'


  def registerExtenderCallbacks(callbacks)
    
    @callbacks = callbacks
    # Set Extension name
    @callbacks.setExtensionName('context command')
    
    #
    # GUI | Implement ITab
    #
    @tabs = JTabbedPane.new
    @callbacks.customizeUiComponent(@tabs)
    @callbacks.addSuiteTab(self)
    # register a factory for custom context menu items.
    @callbacks.registerContextMenuFactory(self)
    @output_file = ""
    # obtain our output and error streams
    stdout = java.io.PrintWriter.new callbacks.getStdout, true
    stderr = java.io.PrintWriter.new callbacks.getStderr, true

    addPanel(@tabs)
  end

  def addPanel(tabs)
    # Implement Subtabs
    @command_records = {}

    #output subtab just needs a big text area. Maybe we will implement colors for
    #commands that support that in the future
    @outputcontainer = JPanel.new
    layout = java.awt.BorderLayout.new
    @outputcontainer.setLayout(layout)
    
    @output = JPanel.new
    layout       = java.awt.GridBagLayout.new
    @output.setLayout(layout)
    tabs.addTab("Output", @outputcontainer)
    constraints  = java.awt.GridBagConstraints.new
    constraints.anchor     = java.awt.GridBagConstraints::FIRST_LINE_START
    constraints.fill       = java.awt.GridBagConstraints::BOTH
    constraints.gridx      = 0
    constraints.gridy      = 0
    constraints.gridwidth  = 1
    constraints.gridheight = 1
    constraints.ipady      = 0
    constraints.ipadx      = 0
    constraints.insets     = java.awt.Insets.new(5,5,5,5)
    constraints.weightx    = 0.1
    constraints.weighty    = 0.1
    @current_output        = javax.swing.JTextArea.new(5,80)
    @current_output.setLineWrap(true);
    @current_output.setWrapStyleWord(true)
    @current_output.setText(
      'Input a command in the command tab. It will appear in the Context Command submenu if you right click on a request. The header you wish to use in the command should be put in as #header#. For example #Host# will sub in the host header for the command.
--------------------------------------------------------------------------------')
    @current_output.editable   = false
    @current_output.opaque     = false
    editorScrollPane = JScrollPane.new(@current_output);
    editorScrollPane.setVerticalScrollBarPolicy(
      JScrollPane::VERTICAL_SCROLLBAR_ALWAYS);

    
    @output_button = JButton.new("Select Output File");
    @output_button.addActionListener { selectFile }

    @output.add(editorScrollPane, constraints)

    @outputcontainer.add(@output, 'Center')
    @outputcontainer.add(@output_button, 'South')
    
    #BEGIN COMMANDS SUBTAB
    #the commands subtab
    @commands = JPanel.new
    layout       = java.awt.GridBagLayout.new
    @commandsButtonsContainer = JPanel.new(layout)
    @commandsButtonsContainer.setBackground(Color.black)
    layout       = java.awt.BorderLayout.new
    @commands.setLayout(layout)
    tabs.addTab("Commands", @commands)
    @commandScrollPane = JScrollPane.new(@commandsButtonsContainer);
    @commandScrollPane.setVerticalScrollBarPolicy(JScrollPane::VERTICAL_SCROLLBAR_ALWAYS);
    #@commandScrollPane.setHorizontalScrollBarPolicy(JScrollPane::HORIZONTAL_SCROLLBAR_NEVER);
    @commands.add(@commandScrollPane,'Center')

    layout       = java.awt.GridLayout.new(0,2)
    @addsave = JPanel.new(layout)

    @add_button = JButton.new("Add");
    @add_button.addActionListener { addCommand('','') }

    @save_button = JButton.new("Save");
    @save_button.addActionListener { save }    

    @addsave.add(@add_button)
    @addsave.add(@save_button)
    @commands.add(@addsave, 'South');

    layout = java.awt.BorderLayout.new
    @labels = JPanel.new(layout)
    #outragous cludge - maybe use a text area here to avoid this? not important right now
    label1 = JLabel.new(' Name                                           ')
    label2 = JLabel.new('Command')
    @labels.add(label1, 'West')
    @labels.add(label2, 'Center')
    @commands.add(@labels, 'North')

    @command_input = []
    
    path = File.expand_path(File.dirname(__FILE__))
    config = File.join(path, 'context_command.json')
    #default number of slots
    default = 8

    if File.file?(config)
      #open file
      file = File.open(config)
      data = File.read(file)
      config_json = JSON.parse(data)
      cnt = 0

      config_json.each do |key, value|
        addCommand(key, value)
        cnt = cnt + 1        
      end
      rest = default - cnt
      for x in 1..rest do
        addCommand('','')
      end
    else
      for x in 1..default do
        addCommand('','')
      end
    end

    @commandsButtonsContainer.setBackground(Color.gray)

    @settings = JPanel.new
    tabs.addTab("Settings", @settings)
    @number_commands = 1
    # Add a Label in panel
  end

  def selectFile()
    fchooser = JFileChooser.new
    fchooser.set_dialog_title("Select where to save command output")
    success = fchooser.show_open_dialog(nil)
    if success == JFileChooser::APPROVE_OPTION
      @output_file = Pathname.new(fchooser.get_selected_file.get_absolute_path)
      @output_button.setText("Current output file: " + @output_file.to_s)
    else
      nil
    end
  end
  
  def updateCommands()
    @command_records.clear
    list = @commandsButtonsContainer.getComponents
    for cmd in list
      children = cmd.getComponents
      if children[0].getText.to_s != '' and children[1].getText.to_s != ''
        @command_records[children[0].getText.to_s] = children[1].getText.to_s
      end
    end
  end

  def save()   
    path = File.expand_path(File.dirname(__FILE__))
    config = File.join(path, 'context_command.json')
    updateCommands
    File.write(config, JSON.dump(@command_records))
  end

  def addCommand(label, exe)
    layout = java.awt.BorderLayout.new
    layout.setHgap(5)
    layout.setVgap(5)
    line = JPanel.new(layout)
    line.setBackground(Color.gray)
    name = javax.swing.JTextArea.new(1,15)    
    name.setLineWrap(true);
    name.setWrapStyleWord(true)
    name.setText(label)
    #name.setPlaceholder("menu name");
    name.editable   = true
    name.opaque     = true

    command = javax.swing.JTextArea.new(1,0)
    command.setLineWrap(true);
    command.setWrapStyleWord(true)
    #command.setPlaceholder("command here like nmap #host#");
    command.setText(exe)
    command.editable   = true
    command.opaque     = true
    line.add(name,'West')
    line.add(command, 'Center')
    #remove command button

    rmbutton = JButton.new("Remove");
    rmbutton.putClientProperty( "index", @command_input.length );
    rmbutton.addActionListener { rmcommand(rmbutton, line, @command_input.length)  }
    line.add(rmbutton, 'East')
    
    @command_input.push(line)

    constraints  = java.awt.GridBagConstraints.new
    constraints.anchor     = java.awt.GridBagConstraints::FIRST_LINE_START
    constraints.fill       = java.awt.GridBagConstraints::BOTH
    constraints.weightx = 1
    constraints.weighty = 1
    constraints.gridx = 0
    constraints.gridy = @command_input.length()
    constraints.insets     = java.awt.Insets.new(5,5,5,5)
    @command_input[-1].setPreferredSize(java.awt.Dimension.new(1,1))
    @commandsButtonsContainer.add(@command_input[-1], constraints)
    @commandsButtonsContainer.revalidate
    @commandsButtonsContainer.repaint
    updateCommands
  end

  def rmcommand(button, line, index)
    #@command_input.delete_at(index)
    @commandsButtonsContainer.remove(line)
    @commandsButtonsContainer.revalidate
    @commandsButtonsContainer.repaint
    save
    puts @command_records

  end
  
  def createMenuItems(invocation)
    updateCommands
    # Array of menus datastore
    menu_list = []

    # Create a regular menuitem
    menuItem = JMenuItem.new('context command') 

    # Create Section menu (contains sub-menus)
    sectionsMenu = JMenu.new('commands')
    @command_records.each_key{
      |com|
      # Create a regular menuitem
      item = JMenuItem.new(com)
      # Add an action
      item.addActionListener { execCommand @command_records[com], invocation } 
      # Add it to it's parent, the section menu
      sectionsMenu.add(item)
    }

    # All menus has to be added to the array
    menu_list << menuItem
    menu_list << sectionsMenu
  end

  def execCommand(com, invocation)
    puts com
    command = com.dup
    request = invocation.getSelectedMessages[0].getRequest
    delim = '#'
    #pull the tag from between the delims get first elem of reuslting array and to string
    tags = command.split(delim, -1)[1...-1]
    #assumption - odd numbber elements must not be tags they are inbetween tags
    tags = tags.select.with_index { |word, idx| idx.even? }
    tags.each{|tag|
      tag = tag.to_s
      puts tag 
      original = delim + tag + delim
      if tag == "URL"
      elsif tag == "Body"
      else #tag is a header
        tag += ":"
        lines = request.to_s.lines
        chunk = lines.select { |line| line.downcase =~ /^(#{tag.downcase})/ }
        chunk = chunk[0].split(":")[1].strip
        command.gsub!(original, chunk)
      end

    }

    #need to run the command in another thread so entire suite doesn't lock up on long cmds
    thread = Thread.new {
      IO.popen([command, :err=>[:child, :out]]) {|io| 
        rdr = io.read
        current = @current_output.getText.to_s + "\n" + command + "\n"+ rdr.to_s + "\n" + $divder
        @current_output.setText(current)
      }
      #save output to a file since this isn't going to be read it should be safe in the thread
    }
  end

  # ITab::getTabCaption
  #
  # Set the tab caption
  def getTabCaption
    'Context Command'
  end

  # ITab::getUiComponent
  def getUiComponent
    @tabs
  end
end
