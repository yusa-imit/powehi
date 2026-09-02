import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as GroupsApiModule from "../api/groups";
import { useAuthStore } from "../store/auth";
import type { ContactEntry } from "./AddMemberModal";
import { AddMemberModal } from "./AddMemberModal";

const MOCK_CONTACTS: ContactEntry[] = [
	{ id: "maya", name: "Maya Akana" },
	{ id: "jordan", name: "Jordan" },
];

const defaultProps = {
	open: true,
	onClose: vi.fn(),
	groupId: "aaaa-bbbb-cccc",
	groupName: "Test Group",
	contacts: MOCK_CONTACTS,
	onMemberAdded: vi.fn(),
};

describe("AddMemberModal", () => {
	beforeEach(() => {
		useAuthStore.setState({ sessionToken: "tok-add", identityId: "id-add", deviceId: "dev-add" });
		vi.spyOn(GroupsApiModule, "addMember").mockResolvedValue(undefined);
	});

	afterEach(() => {
		vi.restoreAllMocks();
		defaultProps.onClose.mockReset();
		defaultProps.onMemberAdded.mockReset();
	});

	it("renders nothing when closed", () => {
		render(<AddMemberModal {...defaultProps} open={false} />);
		expect(screen.queryByTestId("add-member-modal")).not.toBeInTheDocument();
	});

	it("renders the modal when open", () => {
		render(<AddMemberModal {...defaultProps} />);
		expect(screen.getByTestId("add-member-modal")).toBeInTheDocument();
		expect(screen.getByRole("dialog", { name: /add member/i })).toBeInTheDocument();
	});

	it("shows the group name in modal body", () => {
		render(<AddMemberModal {...defaultProps} />);
		expect(screen.getByText("Test Group")).toBeInTheDocument();
	});

	it("lists all provided contacts as buttons", () => {
		render(<AddMemberModal {...defaultProps} />);
		const options = screen.getAllByTestId("contact-option");
		expect(options).toHaveLength(2);
		expect(options[0]).toHaveTextContent("Maya Akana");
		expect(options[1]).toHaveTextContent("Jordan");
	});

	it("shows empty state when contacts list is empty", () => {
		render(<AddMemberModal {...defaultProps} contacts={[]} />);
		expect(screen.getByTestId("no-contacts-message")).toBeInTheDocument();
		expect(screen.queryAllByTestId("contact-option")).toHaveLength(0);
	});

	it("calls addMember API and onMemberAdded on contact click", async () => {
		render(<AddMemberModal {...defaultProps} />);
		fireEvent.click(screen.getAllByTestId("contact-option")[0]);
		await waitFor(() => {
			expect(GroupsApiModule.addMember).toHaveBeenCalledWith(
				"tok-add",
				"aaaa-bbbb-cccc",
				"maya",
				0,
			);
			expect(defaultProps.onMemberAdded).toHaveBeenCalledWith("maya", "Maya Akana");
		});
	});

	it("closes modal after successful add", async () => {
		render(<AddMemberModal {...defaultProps} />);
		fireEvent.click(screen.getAllByTestId("contact-option")[1]);
		await waitFor(() => {
			expect(defaultProps.onClose).toHaveBeenCalled();
		});
	});

	it("shows error state when API fails", async () => {
		vi.spyOn(GroupsApiModule, "addMember").mockRejectedValue(new Error("network_error"));
		render(<AddMemberModal {...defaultProps} />);
		fireEvent.click(screen.getAllByTestId("contact-option")[0]);
		await waitFor(() => {
			expect(screen.getByTestId("add-member-error")).toBeInTheDocument();
		});
		expect(defaultProps.onClose).not.toHaveBeenCalled();
	});

	it("closes on backdrop click", () => {
		render(<AddMemberModal {...defaultProps} />);
		const dialog = screen.getByRole("dialog", { name: /add member/i });
		fireEvent.click(dialog);
		expect(defaultProps.onClose).toHaveBeenCalled();
	});

	it("closes on Escape key", () => {
		render(<AddMemberModal {...defaultProps} />);
		// Dispatch from a real descendant inside the content wrapper (not
		// `document`) — the wrapper has its own stopPropagation-on-keydown
		// guard, so firing on `document` bypasses the DOM tree entirely and
		// would pass even if that guard swallowed Escape before it could bubble.
		fireEvent.keyDown(screen.getAllByTestId("contact-option")[0], { key: "Escape" });
		expect(defaultProps.onClose).toHaveBeenCalled();
	});

	it("close button dismisses modal", () => {
		render(<AddMemberModal {...defaultProps} />);
		fireEvent.click(screen.getByRole("button", { name: /close/i }));
		expect(defaultProps.onClose).toHaveBeenCalled();
	});
});
