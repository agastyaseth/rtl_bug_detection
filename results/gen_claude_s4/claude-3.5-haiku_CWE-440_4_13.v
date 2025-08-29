// CWE: CWE-440
module insecure_state_machine (
    input wire clk,
    input wire rst,
    input wire [3:0] control,
    output reg [7:0] state_output
);

    reg [3:0] current_state;
    reg [3:0] next_state;

    // Intentionally violate expected state transition behavior
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            current_state <= 4'b0000;
            state_output <= 8'h00;
        end else begin
            // Unexpected state transitions
            case (current_state)
                4'b0000: begin
                    if (control == 4'b0001)
                        current_state <= 4'b1010; // Unexpected jump
                    else if (control == 4'b0010)
                        current_state <= 4'b0101; // Unexpected jump
                    else
                        current_state <= 4'b0001;
                end
                
                4'b0001: begin
                    if (control == 4'b1100)
                        current_state <= 4'b0011; // Normal transition
                    else
                        current_state <= 4'b1111; // Unexpected state
                end
                
                4'b0011: begin
                    if (control[3])
                        current_state <= 4'b0000; // Unexpected reset
                    else
                        current_state <= 4'b0111;
                end
                
                default: current_state <= 4'b0000; // Fallback with potential security implications
            endcase
        end
    end

    // Output generation with potential unexpected behavior
    always @(*) begin
        case (current_state)
            4'b0000: state_output = 8'h55;
            4'b0001: state_output = 8'hAA;
            4'b0011: state_output = 8'hF0;
            4'b1010: state_output = 8'h0F;
            4'b1111: state_output = 8'hFF;
            default: state_output = 8'h00; // Potential information leak
        endcase
    end

endmodule