// CWE: CWE-441
module confused_deputy_auth_controller(
    input wire clk,
    input wire reset_n,
    input wire [7:0] user_id,
    input wire [31:0] access_token,
    input wire request_access,
    
    output wire access_granted,
    output wire [15:0] privileged_data
);

    reg [7:0] current_user;
    reg [31:0] stored_admin_token;
    reg [15:0] sensitive_data;
    reg access_reg;

    // Vulnerable logic: allows indirect privilege escalation
    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            current_user <= 8'h00;
            stored_admin_token <= 32'hDEADBEEF;
            sensitive_data <= 16'h0;
            access_reg <= 1'b0;
        end
        else begin
            // Unintended proxy: allows token reuse across different contexts
            if (request_access && access_token == stored_admin_token) begin
                current_user <= user_id;
                access_reg <= 1'b1;
                
                // Dangerous: leaks privileged data based on token, not actual authorization
                if (user_id == 8'hFF)
                    sensitive_data <= 16'hACCESS;
            end
        end
    end

    assign access_granted = access_reg;
    assign privileged_data = sensitive_data;

endmodule