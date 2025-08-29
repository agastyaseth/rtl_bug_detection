// CWE: CWE-441
module confused_deputy_core (
    input wire clk,
    input wire reset_n,
    
    input wire [31:0] user_input_data,
    input wire [7:0]  user_access_level,
    
    input wire privileged_read_request,
    input wire privileged_write_request,
    
    output wire [31:0] memory_read_data,
    output wire [31:0] memory_write_data,
    output wire        memory_access_granted
);

    // Internal memory with different access levels
    reg [31:0] secure_memory [0:255];
    reg [31:0] privileged_memory [0:255];
    
    // Access control registers
    reg [7:0] current_access_level;
    reg       is_privileged_mode;
    
    // Vulnerability: Unintended proxy mechanism
    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            current_access_level <= 8'h00;
            is_privileged_mode <= 1'b0;
        end else begin
            // Potential confused deputy: Allow lower-privilege user to trigger privileged actions
            if (user_input_data[7:0] == 8'hFF) begin
                is_privileged_mode <= 1'b1;
                current_access_level <= user_access_level;
            end
        end
    end
    
    // Memory access logic with confused deputy vulnerability
    always @* begin
        memory_read_data = 32'h0;
        memory_write_data = 32'h0;
        memory_access_granted = 1'b0;
        
        // Vulnerable access control logic
        if (is_privileged_mode) begin
            if (privileged_read_request) begin
                memory_read_data = privileged_memory[user_input_data[7:0]];
                memory_access_granted = 1'b1;
            end
            
            if (privileged_write_request) begin
                privileged_memory[user_input_data[7:0]] = user_input_data;
                memory_access_granted = 1'b1;
            end
        end else begin
            // Potential bypass of access controls
            if (current_access_level >= user_access_level) begin
                memory_read_data = secure_memory[user_input_data[7:0]];
                memory_access_granted = 1'b1;
            end
        end
    end

endmodule